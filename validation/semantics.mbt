///|
fn location_key(at : @openapi.Location, key : String) -> @openapi.Location {
  {
    uri: at.uri,
    pointer: at.pointer +
    "/" +
    key.replace_all(old="~", new="~0").replace_all(old="/", new="~1"),
  }
}

///|
fn semantic_issue(
  violations : Array[Violation],
  at : @openapi.Location,
  keyword : String,
  message : String,
) -> Unit {
  violations.push({ keyword, message, location: at, schema_pointer: "", })
}

///|
fn security_names(
  value : Json?,
  at : @openapi.Location,
  schemes : Map[String, Json],
  violations : Array[Violation],
) -> Unit {
  if value is Some(Array(requirements)) {
    for index, requirement in requirements {
      if requirement is Object(fields) {
        for name in fields.keys() {
          if !schemes.contains(name) {
            semantic_issue(
              violations,
              location_key(location_key(at, index.to_string()), name),
              "securityScheme",
              "Security requirement names an undeclared security scheme: " +
              name,
            )
          }
        }
      }
    }
  }
}

///|
fn parameter_list(
  value : Json?,
  at : @openapi.Location,
  violations : Array[Violation],
) -> (Map[(String, String), Bool], Bool) {
  let result = Map([])
  let mut complete = true
  if value is Some(Array(parameters)) {
    for index, parameter in parameters {
      if parameter is Object(fields) {
        if fields.contains("$ref") {
          complete = false
          continue
        }
        if fields.get("name") is Some(String(name)) &&
          fields.get("in") is Some(String(position)) {
          let key = (
            position,
            if position == "header" {
              name.to_lower()
            } else {
              name
            },
          )
          if result.contains(key) {
            semantic_issue(
              violations,
              location_key(at, index.to_string()),
              "parameterIdentity",
              "Duplicate parameter identity: " + position + " " + name,
            )
          }
          result[key] = true
        }
      }
    }
  }
  (result, complete)
}

///|
fn semantic_checks(
  value : Json,
  source : String,
  violations : Array[Violation],
) -> Unit {
  let root = match value {
    Object(fields) => fields
    _ => return
  }
  let at : @openapi.Location = { uri: source, pointer: "", }
  let schemes = match root.get("components") {
    Some(Object(components)) =>
      match components.get("securitySchemes") {
        Some(Object(schemes)) => schemes
        _ => Map([])
      }
    _ => Map([])
  }
  security_names(
    root.get("security"),
    location_key(at, "security"),
    schemes,
    violations,
  )
  let paths = match root.get("paths") {
    Some(Object(paths)) => paths
    _ => return
  }
  let ids = Map([])
  let keys = paths.keys().collect()
  keys.sort()
  for path in keys {
    if path.has_prefix("x-") {
      continue
    }
    let item = match paths[path] {
      Object(item) => item
      _ => continue
    }
    let item_at = location_key(location_key(at, "paths"), path)
    let (inherited, path_complete) = parameter_list(
      item.get("parameters"),
      location_key(item_at, "parameters"),
      violations,
    )
    for
      verb in [
        "delete", "get", "head", "options", "patch", "post", "put", "trace",
      ] {
      if item.get(verb) is Some(Object(operation)) {
        let operation_at = location_key(item_at, verb)
        if operation.get("operationId") is Some(String(id)) {
          if ids.contains(id) {
            semantic_issue(
              violations,
              location_key(operation_at, "operationId"),
              "operationId",
              "operationId must be unique: " + id,
            )
          }
          ids[id] = true
        }
        security_names(
          operation.get("security"),
          location_key(operation_at, "security"),
          schemes,
          violations,
        )
        let (declared, operation_complete) = parameter_list(
          operation.get("parameters"),
          location_key(operation_at, "parameters"),
          violations,
        )
        if path_complete && operation_complete && !item.contains("$ref") {
          let mut start = None
          for index in 0..<path.length() {
            if path[index] == '{' {
              start = Some(index + 1)
            } else if path[index] == '}' && start is Some(begin) {
              let name = path[begin:index].to_owned()
              if !inherited.contains(("path", name)) &&
                !declared.contains(("path", name)) {
                semantic_issue(
                  violations,
                  location_key(operation_at, "parameters"),
                  "pathParameter",
                  "Path template has no corresponding parameter: " + name,
                )
              }
              start = None
            }
          }
        }
      }
    }
  }
}
