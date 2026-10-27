///|
fn diagnostic(error : AuthError, source : String) -> Diagnostic {
  let AuthError(code, message, pointer) = error
  { code, message, location: { uri: source, pointer, }, }
}

///|
fn minor_version(version : String) -> Int32? {
  let pieces = version.split(".").map(StringView::to_owned).collect()
  if pieces.length() != 3 || pieces[0] != "3" || pieces[2].is_empty() {
    return None
  }
  if !pieces[2].iter().all(c => c >= '0' && c <= '9') {
    return None
  }
  match pieces[1] {
    "0" => Some(0)
    "1" => Some(1)
    _ => None
  }
}

///|
fn Context::operation(
  self : Context,
  value : Value,
  verb : String,
  path : String,
  pointer : String,
  inherited : (@logic.Policy?, Array[String]),
  inherited_location : String,
  diagnostics : Array[Diagnostic],
) -> Operation {
  let mut operation_id = None
  let mut policy = None
  let mut schemes = []
  let mut security_location = pointer_key(pointer, "security")
  try {
    let obj = object(value, pointer)
    if obj.contains("$ref") {
      issue(
        "auth.operation",
        "Operation Object does not support $ref; reference a Path Item instead",
        pointer_key(pointer, "$ref"),
      )
    }
    if obj.get("operationId") is Some(value) {
      operation_id = Some(string(value, pointer_key(pointer, "operationId")))
    }
    match obj.get("security") {
      Some(value) => {
        let (parsed, used) = self.security(value, security_location)
        policy = Some(parsed)
        schemes = used
      }
      None => {
        policy = inherited.0
        schemes = inherited.1.copy()
        security_location = inherited_location
      }
    }
  } catch {
    error => diagnostics.push(diagnostic(error, self.source))
  }
  {
    http_method: verb.to_upper(),
    path,
    operation_id,
    policy,
    location: { uri: self.source, pointer, },
    security_location: { uri: self.source, pointer: security_location, },
    schemes,
  }
}

///|
/// Parse one OpenAPI 3.0/3.1 document and extract effective `paths` security.
///
/// Syntax, root and version errors raise. Authentication errors are attached to
/// the document and leave affected operation policies as `None`, so callers can
/// still compare other operations. Input, reference and policy limits are fixed.
pub fn parse_document(
  text : String,
  format~ : InputFormat,
  source~ : String = "<input>",
) -> Document raise DocumentError {
  let root = read_input(text, format) catch {
    DocumentError(message) => raise DocumentError(source + ": " + message)
  }
  let obj = match root {
    Obj(obj) => obj
    _ => raise DocumentError(source + ": OpenAPI root must be an object")
  }
  let minor = match obj.get("openapi") {
    Some(Str(version)) =>
      match minor_version(version) {
        Some(minor) => minor
        None =>
          raise DocumentError(
            source + ": Supported OpenAPI versions are 3.0.x and 3.1.x",
          )
      }
    _ =>
      raise DocumentError(
        source + ": openapi must be a 3.0.x or 3.1.x version string",
      )
  }
  let diagnostics = []
  let declared = try {
    match obj.get("components") {
      None => {}
      Some(value) => {
        let components = object(value, "/components")
        match components.get("securitySchemes") {
          None => {}
          Some(value) => object(value, "/components/securitySchemes")
        }
      }
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error, source))
      {}
    }
  }
  let context = { root, source, minor, declared, cache: {}, }
  // Valid unused declarations matter when requirements change between schemes.
  // Invalid unused declarations do not invalidate unrelated operation analysis.
  for name in sorted_keys(declared) {
    ignore(context.scheme(name)) catch {
      _ => ()
    }
  }
  let inherited_location = if obj.contains("security") {
    "/security"
  } else {
    ""
  }
  let inherited = try {
    match obj.get("security") {
      None => (Some(@logic.Policy::anonymous()), [])
      Some(value) => {
        let (policy, used) = context.security(value, "/security")
        (Some(policy), used)
      }
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error, source))
      (None, [])
    }
  }
  let paths = try {
    match obj.get("paths") {
      Some(value) => object(value, "/paths")
      None => {
        if minor == 0 {
          issue("auth.required", "OpenAPI 3.0 requires paths", "/paths")
        }
        {}
      }
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error, source))
      {}
    }
  }
  let operations = []
  let methods = [
    "delete", "get", "head", "options", "patch", "post", "put", "trace",
  ]
  for path in sorted_keys(paths) {
    if path.has_prefix("x-") {
      continue
    }
    let pointer = pointer_key("/paths", path)
    try {
      if !path.has_prefix("/") {
        issue("auth.path", "OpenAPI path must begin with /", pointer)
      }
      let (item, location) = context.resolve(paths[path], pointer)
      for key in item.keys() {
        if !methods.contains(key) &&
          key != "summary" &&
          key != "description" &&
          key != "servers" &&
          key != "parameters" &&
          !key.has_prefix("x-") {
          issue(
            "ref.target",
            "Unsupported Path Item field: " + key,
            pointer_key(location, key),
          )
        }
      }
      for verb in methods {
        if item.get(verb) is Some(value) {
          operations.push(
            context.operation(
              value,
              verb,
              path,
              pointer_key(location, verb),
              inherited,
              inherited_location,
              diagnostics,
            ),
          )
        }
      }
    } catch {
      error => diagnostics.push(diagnostic(error, source))
    }
  }
  let schemes = []
  for name in sorted_keys(context.cache) {
    schemes.push(context.cache[name].public_scheme)
  }
  { source, operations, schemes, diagnostics, }
}
