///|
fn canonical_path_for(path : String, directory : Bool) -> String raise {
  if path.contains_char('\u0000') {
    raise CliError("local path contains a NUL character")
  }
  let output = Bytes::make(262144, 0)
  let absolute = @path.Path(path).resolve().to_string()
  let length = canonical_path(
    @utf8.encode(absolute),
    output,
    if directory {
      1
    } else {
      0
    },
  )
  if length < 0 {
    raise CliError(
      "cannot canonicalize local \{if directory { "directory" } else { "file" }}: \{path}",
    )
  }
  @utf8.decode(output[0:length])
}

///|
fn canonical_root(path : String) -> String raise {
  canonical_path_for(path, true)
}

///|
fn canonical_source_uri(path : String) -> String raise {
  file_uri(canonical_path_for(path, false))
}

///|
fn uri_hex(byte : Byte) -> Int32 {
  let number = byte.to_int()
  if number >= 48 && number <= 57 {
    number - 48
  } else if number >= 65 && number <= 70 {
    number - 55
  } else if number >= 97 && number <= 102 {
    number - 87
  } else {
    -1
  }
}

///|
fn source_path(source : String) -> String raise {
  if !source.has_prefix("file:///") ||
    source.contains_char('?') ||
    source.contains_char('#') {
    raise CliError("local references require a canonical local file URI")
  }
  let encoded = @utf8.encode(source[7:].to_owned())
  let decoded : Array[Byte] = []
  let mut index = 0
  while index < encoded.length() {
    if encoded[index] == b'%' {
      if index + 2 >= encoded.length() {
        raise CliError("invalid percent escape in local file URI")
      }
      let high = uri_hex(encoded[index + 1])
      let low = uri_hex(encoded[index + 2])
      if high < 0 || low < 0 {
        raise CliError("invalid percent escape in local file URI")
      }
      decoded.push((high * 16 + low).to_byte())
      index += 3
    } else {
      decoded.push(encoded[index])
      index += 1
    }
  }
  let path = @utf8.decode(Bytes::from_array(decoded))
  if path.contains_char('\u0000') {
    raise CliError("local file URI contains a NUL character")
  }
  if path.has_prefix("//") {
    raise CliError("network file URIs are not supported")
  }
  if @path.sep == '\\' && path.has_prefix("/") {
    path[1:].to_owned()
  } else {
    path
  }
}

///|
fn relative_within(root : String, candidate : String) -> String raise {
  let boundary = root
    .replace_all(old="\\", new="/")
    .trim_end(chars="/")
    .to_owned()
  let target = candidate.replace_all(old="\\", new="/")
  let prefix = boundary + "/"
  if target.length() <= prefix.length() {
    raise CliError("local reference must name a file within the reference root")
  }
  let actual_prefix = target[0:prefix.length()].to_owned()
  let matches = if @path.sep == '\\' {
    actual_prefix.equal_ignore_ascii_case(prefix)
  } else {
    actual_prefix == prefix
  }
  if !matches {
    raise CliError("local reference escapes the reference root")
  }
  target[prefix.length():].to_owned()
}

///|
fn load_local_reference(
  root : String,
  from : String,
  relative : String,
) -> @openapi.SourceDocument raise @openapi.DocumentError {
  load_local_reference_inner(root, from, relative) catch {
    error => raise @openapi.DocumentError::DocumentError(error.to_string())
  }
}

///|
fn load_local_reference_inner(
  root : String,
  from : String,
  relative : String,
) -> @openapi.SourceDocument raise {
  if relative == "" ||
    relative.has_prefix("/") ||
    relative.contains_char('\\') ||
    relative.contains_char(':') ||
    relative.contains_char('\u0000') ||
    relative.contains_char('?') {
    raise CliError(
      "local reference must use a relative local path without a query",
    )
  }
  let candidate = @path.Path(source_path(from))
    .dirname()
    .join(@path.Path(relative))
    .resolve()
    .to_string()
  let path = relative_within(root, candidate)
  let format = match @path.Path(path).extname().to_owned() {
    ".json" => @openapi.Json
    ".yaml" | ".yml" => @openapi.Yaml
    _ =>
      raise CliError("local reference must name a .json, .yaml, or .yml file")
  }
  let output = Bytes::make(16777217, 0)
  let canonical = Bytes::make(262144, 0)
  let length = read_confined(
    @utf8.encode(root),
    @utf8.encode(path),
    output,
    canonical,
  )
  match length {
    -1 => raise CliError("cannot open local reference: \{relative}")
    -2 => raise CliError("cannot read local reference: \{relative}")
    -3 => raise CliError("local reference must be a regular file: \{relative}")
    -4 => raise CliError("local reference exceeds 16 MiB: \{relative}")
    -5 =>
      raise CliError(
        "local reference crosses a symlink, reparse point, or root boundary: \{relative}",
      )
    _ if length > 16777216 =>
      raise CliError("local reference exceeds 16 MiB: \{relative}")
    _ => ()
  }
  let mut path_length = 0
  while path_length < canonical.length() && canonical[path_length] != 0 {
    path_length += 1
  }
  {
    text: @utf8.decode(output[0:length]),
    format,
    source: file_uri(@utf8.decode(canonical[0:path_length])),
  }
}
