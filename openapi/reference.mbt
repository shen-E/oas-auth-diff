///|
fn hex_digit(value : Int32) -> Int32? {
  if value >= 48 && value <= 57 {
    Some(value - 48)
  } else if value >= 65 && value <= 70 {
    Some(value - 55)
  } else if value >= 97 && value <= 102 {
    Some(value - 87)
  } else {
    None
  }
}

///|
fn decode_percent(text : String, location : Location) -> String raise AuthError {
  let bytes = @utf8.encode(text)
  let out = @buffer.Buffer()
  let mut index = 0
  while index < bytes.length() {
    if bytes[index] == b'%' {
      if index + 2 >= bytes.length() {
        issue("ref.pointer", "Truncated percent escape in $ref", location)
      }
      match
        (
          hex_digit(bytes[index + 1].to_int()),
          hex_digit(bytes[index + 2].to_int()),
        ) {
        (Some(high), Some(low)) => out.write_byte((high * 16 + low).to_byte())
        _ => issue("ref.pointer", "Invalid percent escape in $ref", location)
      }
      index += 3
    } else {
      out.write_byte(bytes[index])
      index += 1
    }
  }
  @utf8.decode(out.to_bytes()) catch {
    _ => {
      issue("ref.pointer", "Invalid UTF-8 in $ref", location)
      abort("unreachable")
    }
  }
}

///|
fn decode_segment(
  segment : String,
  location : Location,
) -> String raise AuthError {
  let out = StringBuilder()
  let chars = segment.to_array()
  let mut index = 0
  while index < chars.length() {
    if chars[index] == '~' {
      if index + 1 >= chars.length() {
        issue("ref.pointer", "Truncated JSON Pointer escape", location)
      }
      match chars[index + 1] {
        '0' => out.write_char('~')
        '1' => out.write_char('/')
        _ => issue("ref.pointer", "Invalid JSON Pointer escape", location)
      }
      index += 2
    } else {
      out.write_char(chars[index])
      index += 1
    }
  }
  out.to_string()
}

///|
fn array_index(key : String, location : Location) -> Int32 raise AuthError {
  let chars = key.to_array()
  if chars.is_empty() || (chars.length() > 1 && chars[0] == '0') {
    issue("ref.pointer", "Invalid JSON Pointer array index", location)
  }
  let mut value = 0
  for char in chars {
    if char < '0' || char > '9' || value > 250000 {
      issue("ref.pointer", "Invalid JSON Pointer array index", location)
    }
    value = value * 10 + char.to_int() - 48
  }
  value
}

///|
fn validate_relative(
  path : String,
  location : Location,
) -> String raise AuthError {
  if path
    .iter()
    .any(c => c == '?' || c == '\\' || c.to_int() <= 32 || c.to_int() == 127) {
    issue(
      "ref.path", "Expected an escaped relative URI path without query or control characters",
      location,
    )
  }
  let decoded = decode_percent(path, location) catch {
    AuthError(_, message, at) => {
      issue("ref.path", message, at)
      abort("unreachable")
    }
  }
  if decoded.is_empty() ||
    decoded.has_prefix("/") ||
    decoded
    .iter()
    .any(c => c == '\\' || c == ':' || c.to_int() < 32 || c.to_int() == 127) {
    issue(
      "ref.path", "Expected a relative URI file path without scheme, query, backslash or control characters",
      location,
    )
  }
  decoded
}

///|
fn Graph::lookup_ref(
  self : Graph,
  reference : String,
  at : Location,
  external~ : Bool = true,
) -> (Value, Location) raise AuthError {
  let (path, fragment) = match reference.split_once("#") {
    Some((path, fragment)) => (path.to_owned(), fragment.to_owned())
    None => (reference, "")
  }
  let uri = if path.is_empty() {
    at.uri
  } else {
    if self.load is None || !external {
      issue(
        "ref.external", "Only same-document #/... references are supported without a loader",
        at,
      )
    }
    self.load_relative(validate_relative(path, at), at)
  }
  let decoded = decode_percent(fragment, at)
  if decoded != "" && !decoded.has_prefix("/") {
    issue(
      "ref.pointer", "Expected an empty fragment or a #/... JSON Pointer", at,
    )
  }
  let mut current = match self.documents.get(uri) {
    Some(cached) =>
      match cached.value {
        Ok(value) => value
        Err(failure) => {
          issue(failure.code, failure.message, at)
          abort("unreachable")
        }
      }
    None => abort("missing current source")
  }
  let mut location : Location = { uri, pointer: "", }
  if decoded != "" {
    for part in decoded.split("/").drop(1) {
      let key = decode_segment(part.to_owned(), at)
      location = location.key(key)
      match current {
        Obj(obj) =>
          current = match obj.get(key) {
            Some(value) => value
            None => {
              issue(
                "ref.missing",
                "Reference target does not exist: " + reference,
                at,
              )
              abort("unreachable")
            }
          }
        Seq(items) =>
          current = match items.get(array_index(key, at)) {
            Some(value) => value
            None => {
              issue("ref.missing", "Reference array index is out of bounds", at)
              abort("unreachable")
            }
          }
        _ =>
          issue(
            "ref.target",
            "Reference traverses a non-object: " + reference,
            at,
          )
      }
    }
  }
  (current, location)
}

///|
fn Graph::resolve(
  self : Graph,
  value : Value,
  at : Location,
  external~ : Bool = true,
) -> (Map[String, Value], Location) raise AuthError {
  let mut current = object(value, at)
  let mut location = at
  let seen : Map[(String, String), Bool] = Map([])
  seen[(at.uri, at.pointer)] = true
  while current.get("$ref") is Some(reference) {
    let reference_location = location.key("$ref")
    let reference = string(reference, reference_location)
    for key in current.keys() {
      if key != "$ref" &&
        key != "summary" &&
        key != "description" &&
        !key.has_prefix("x-") {
        issue(
          "ref.sibling",
          "Conflicting sibling beside $ref: " + key,
          location.key(key),
        )
      }
    }
    let (value, target) = self.lookup_ref(
      reference,
      reference_location,
      external~,
    )
    let identity = (target.uri, target.pointer)
    if seen.contains(identity) {
      issue("ref.cycle", "Circular reference: " + reference, reference_location)
    }
    if seen.length() >= 128 {
      issue(
        "ref.limit", "Reference chain exceeds 128 entries", reference_location,
      )
    }
    seen[identity] = true
    current = object(value, target)
    location = target
  }
  (current, location)
}
