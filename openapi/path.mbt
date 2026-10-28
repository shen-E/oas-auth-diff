///|
/// Normalize nonempty path-template names while preserving every literal.
/// Malformed templates and paths without a leading slash have no identity.
pub fn path_identity(path : String) -> String? {
  if !path.has_prefix("/") {
    return None
  }
  let chars = path.to_array()
  let out = StringBuilder()
  let mut index = 0
  while index < chars.length() {
    match chars[index] {
      '{' => {
        index += 1
        let start = index
        while index < chars.length() && chars[index] != '}' {
          if chars[index] == '{' || chars[index] == '/' {
            return None
          }
          index += 1
        }
        if index == start || index == chars.length() {
          return None
        }
        out.write_string("{}")
      }
      '}' => return None
      char => out.write_char(char)
    }
    index += 1
  }
  Some(out.to_string())
}

///|
fn analyzable_paths(
  paths : Map[String, Value],
  location : Location,
  diagnostics : Array[Diagnostic],
) -> Array[String] {
  let keys = sorted_keys(paths)
  let identities : Map[String, String] = Map([])
  let owners : Map[String, String] = Map([])
  let conflicts : Map[String, Bool] = Map([])
  for path in keys {
    if path.has_prefix("x-") {
      continue
    }
    match path_identity(path) {
      None =>
        diagnostics.push({
          code: "auth.path",
          message: "OpenAPI path must begin with / and contain only nonempty, balanced template names within a segment",
          location: location.key(path),
        })
      Some(identity) => {
        identities[path] = identity
        match owners.get(identity) {
          Some(previous) if previous != path => conflicts[identity] = true
          Some(_) => ()
          None => owners[identity] = path
        }
      }
    }
  }
  let accepted = []
  for path in keys {
    if identities.get(path) is Some(identity) {
      if conflicts.contains(identity) {
        diagnostics.push({
          code: "path-duplicate",
          message: "OpenAPI paths with the same template identity cannot coexist: " +
          identity,
          location: location.key(path),
        })
      } else {
        accepted.push(path)
      }
    }
  }
  accepted
}
