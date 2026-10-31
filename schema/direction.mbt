///|
/// Neutral keeps JSON Schema requiredness. Request/Response use directional
/// requiredness: read-only fields are optional in requests, write-only fields
/// are optional in responses. Present values still obey their Schema.
pub(all) enum Direction {
  Neutral
  Request
  Response
} derive(Eq, Debug)

///|
pub extend Direction with Eq::{equal, not_equal}

///|
pub extend Direction with Debug::{to_repr}

///|
fn annotation_flag(
  fields : Map[String, Json],
  name : String,
) -> Bool raise SchemaError {
  match fields.get(name) {
    None | Some(False) => false
    Some(True) => true
    _ => raise SchemaError(name + " must be a boolean")
  }
}

///|
fn visibility(value : Json, budget : Budget) -> (Bool, Bool) raise SchemaError {
  consume(budget)
  guard value is Object(fields) else { return (false, false) }
  let mut read = annotation_flag(fields, "readOnly")
  let mut write = annotation_flag(fields, "writeOnly")
  if fields.get("allOf") is Some(Array(children)) {
    for child in children {
      let (r, w) = visibility(child, budget)
      read = read || r
      write = write || w
    }
  }
  for keyword in ["anyOf", "oneOf"] {
    if fields.get(keyword) is Some(Array(children)) {
      for child in children {
        let (r, w) = visibility(child, budget)
        if r || w {
          raise SchemaError(
            "Conditional readOnly/writeOnly annotations require instance-dependent projection",
          )
        }
      }
    }
  }
  (read, write)
}

///|
fn object_visibility(
  value : Json,
  budget : Budget,
) -> Map[String, (Bool, Bool)] raise SchemaError {
  consume(budget)
  let result = Map([])
  guard value is Object(fields) else { return result }
  if fields.get("properties") is Some(Object(properties)) {
    for name, child in properties {
      let flags = visibility(child, budget)
      if flags != (false, false) {
        result[name] = flags
      }
    }
  }
  if fields.get("allOf") is Some(Array(children)) {
    for child in children {
      for name, (read, write) in object_visibility(child, budget) {
        let (r, w) = result.get(name).unwrap_or((false, false))
        result[name] = (read || r, write || w)
      }
    }
  }
  for keyword in ["anyOf", "oneOf"] {
    if fields.get(keyword) is Some(Array(children)) {
      for child in children {
        if !object_visibility(child, budget).is_empty() {
          raise SchemaError(
            "Conditional property visibility requires instance-dependent projection",
          )
        }
      }
    }
  }
  result
}

///|
fn project_direction(
  value : Json,
  direction : Direction,
  legacy : Bool,
  inherited : Map[String, (Bool, Bool)],
  budget : Budget,
) -> Json raise SchemaError {
  consume(budget)
  guard value is Object(fields) else { return value }
  let read = annotation_flag(fields, "readOnly")
  let write = annotation_flag(fields, "writeOnly")
  if legacy && read && write {
    raise SchemaError("OpenAPI 3.0 forbids readOnly and writeOnly together")
  }
  if fields.get("format") is Some(value) && !(value is String(_)) {
    raise SchemaError("format must be a string")
  }
  let visible = if direction == Neutral {
    Map([])
  } else {
    object_visibility(value, budget)
  }
  for name, (read, write) in inherited {
    let (r, w) = visible.get(name).unwrap_or((false, false))
    visible[name] = (read || r, write || w)
  }
  let result = Map([])
  for name, child in fields {
    if ["readOnly", "writeOnly", "format"].contains(name) {
      continue
    }
    if name == "required" && child is Array(names) && direction != Neutral {
      let seen = Map([])
      for name in names {
        match name {
          String(name) if !seen.contains(name) => seen[name] = true
          _ => raise SchemaError("required must contain distinct strings")
        }
      }
      result[name] = Json::array(
        names.filter(name => {
          if name is String(name) {
            let (read, write) = visible.get(name).unwrap_or((false, false))
            if read && write {
              raise SchemaError(
                "Both readOnly and writeOnly apply to property: " + name,
              )
            }
            !((direction == Request && read) || (direction == Response && write))
          } else {
            true
          }
        }),
      )
    } else if name == "properties" && child is Object(properties) {
      let projected = Map([])
      for name, schema in properties {
        projected[name] = project_direction(
          schema,
          direction,
          legacy,
          Map([]),
          budget,
        )
      }
      result[name] = Json::object(projected)
    } else if ["allOf", "anyOf", "oneOf"].contains(name) &&
      child is Array(children) {
      result[name] = Json::array(
        children.map(child => {
          project_direction(child, direction, legacy, visible, budget)
        }),
      )
    } else if ["items", "additionalProperties"].contains(name) {
      result[name] = project_direction(
        child,
        direction,
        legacy,
        Map([]),
        budget,
      )
    } else {
      result[name] = child
    }
  }
  Json::object(result)
}
