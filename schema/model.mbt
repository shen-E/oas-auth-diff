///|
pub suberror SchemaError {
  SchemaError(String)
} derive(Debug)

///|
pub extend SchemaError with Debug::{to_repr}

///|
priv enum Model {
  Any
  Never
  Rule(Constraints)
  All(Array[Model])
  Union(Array[Model])
  ExactlyOne(Array[Model])
}

///|
priv struct Constraints {
  types : Array[String]
  values : Array[Json]?
  properties : Map[String, Model]
  required : Array[String]
  additional : Model
  items : Model
  numeric : Bounds
  length : Bounds
  size : Bounds
  count : Bounds
}

///|
/// A bounded, parsed subset of OpenAPI Schema assertions.
pub struct Schema {
  priv model : Model
}

///|
/// An exclusion is returned only with a value accepted by the source and
/// rejected by the target. Unknown never represents a compatibility proof.
pub(all) enum Inclusion {
  Included
  Excluded(Json)
  Unknown(String)
} derive(Debug)

///|
pub extend Inclusion with Debug::{to_repr}

///|
let kinds : Array[String] = [
  "null", "boolean", "integer", "number", "string", "array", "object",
]

///|
priv struct Budget {
  mut remaining : Int32
}

///|
fn consume(budget : Budget) -> Unit raise SchemaError {
  budget.remaining -= 1
  if budget.remaining < 0 {
    raise SchemaError("Schema analysis exceeds 20000 steps")
  }
}

///|
fn read_model(
  value : Json,
  legacy : Bool,
  depth : Int32,
  budget : Budget,
) -> Model raise SchemaError {
  consume(budget)
  if depth > 128 {
    raise SchemaError("Schema depth exceeds 128")
  }
  let fields = match value {
    True if !legacy => return Any
    False if !legacy => return Never
    Object(fields) => fields
    _ => raise SchemaError("Expected a Schema object (or a 3.1 boolean Schema)")
  }
  for key in fields.keys() {
    if ![
        "type", "enum", "properties", "required", "additionalProperties", "items",
        "nullable", "title", "description", "example", "examples", "$comment", "deprecated",
        "allOf", "anyOf", "oneOf", "const", "$defs", "minimum", "maximum", "exclusiveMinimum",
        "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems", "minProperties",
        "maxProperties", "$schema",
      ].contains(key) &&
      !key.has_prefix("x-") {
      raise SchemaError("Unsupported Schema keyword: " + key)
    }
  }
  if fields.get("$schema") is Some(value) {
    match value {
      String(uri) if !legacy &&
        [
          "https://json-schema.org/draft/2020-12/schema", "https://spec.openapis.org/oas/3.1/dialect/2024-11-10",
        ].contains(uri) => ()
      _ => raise SchemaError("Unsupported Schema dialect")
    }
  }
  if fields.get("$defs") is Some(value) {
    if legacy || !(value is Object(_)) {
      raise SchemaError("$defs requires an OpenAPI 3.1 object")
    }
  }
  let types = match fields.get("type") {
    None => kinds.copy()
    Some(String(name)) if kinds.contains(name) && (!legacy || name != "null") =>
      if name == "number" {
        ["integer", "number"]
      } else {
        [name]
      }
    Some(Array(names)) if !legacy && !names.is_empty() => {
      let result = []
      for name in names {
        match name {
          String(name) if kinds.contains(name) && !result.contains(name) =>
            result.push(name)
          _ => raise SchemaError("Invalid or duplicate Schema type")
        }
      }
      if result.contains("number") && !result.contains("integer") {
        result.push("integer")
      }
      result
    }
    _ => raise SchemaError("Invalid Schema type")
  }
  match fields.get("nullable") {
    Some(True) if legacy =>
      // OAS 3.0 nullable only extends an explicitly specified type.
      if fields.contains("type") && !types.contains("null") {
        types.push("null")
      }
    Some(False) if legacy => ()
    None => ()
    _ => raise SchemaError("nullable requires an OpenAPI 3.0 boolean")
  }
  let mut values = match fields.get("enum") {
    None => None
    Some(Array(values)) if !values.is_empty() => {
      let seen = Map([])
      for value in values {
        consume(budget)
        let key = identity(value)
        if seen.contains(key) {
          raise SchemaError("Duplicate enum value")
        }
        seen[key] = true
      }
      Some(values.map(copy_value))
    }
    _ => raise SchemaError("enum must be a nonempty array")
  }
  if fields.get("const") is Some(value) {
    if legacy {
      raise SchemaError("const requires OpenAPI 3.1")
    }
    values = match values {
      None => Some([copy_value(value)])
      Some(values) => Some(values.filter(v => identity(v) == identity(value)))
    }
  }
  let properties = Map([])
  match fields.get("properties") {
    Some(Object(fields)) =>
      for (name, child) in fields {
        properties[name] = read_model(child, legacy, depth + 1, budget)
      }
    None => ()
    _ => raise SchemaError("properties must be an object")
  }
  let required = match fields.get("required") {
    None => []
    Some(Array(names)) => {
      let result = []
      for name in names {
        match name {
          String(name) if !result.contains(name) => result.push(name)
          _ => raise SchemaError("required must contain distinct strings")
        }
      }
      result
    }
    _ => raise SchemaError("required must be an array")
  }
  let additional = match fields.get("additionalProperties") {
    None | Some(True) => Any
    Some(False) => Never
    Some(value) => read_model(value, legacy, depth + 1, budget)
  }
  let items = match fields.get("items") {
    None => Any
    Some(value) => read_model(value, legacy, depth + 1, budget)
  }
  let numeric = read_numeric(fields, legacy)
  let length = read_size(fields, "minLength", "maxLength")
  let size = read_size(fields, "minItems", "maxItems")
  let count = read_size(fields, "minProperties", "maxProperties")
  let base = if types.length() == kinds.length() &&
    values is None &&
    properties.is_empty() &&
    required.is_empty() &&
    additional is Any &&
    items is Any &&
    bounds_empty(numeric) &&
    bounds_empty(length) &&
    bounds_empty(size) &&
    bounds_empty(count) {
    Any
  } else {
    Rule({
      types,
      values,
      properties,
      required,
      additional,
      items,
      numeric,
      length,
      size,
      count,
    })
  }
  let mut result = base
  for keyword in ["allOf", "anyOf", "oneOf"] {
    if fields.get(keyword) is Some(value) {
      let values = match value {
        Array(values) if !values.is_empty() => values
        _ => raise SchemaError(keyword + " must be a nonempty Schema array")
      }
      let children = []
      for child in values {
        children.push(read_model(child, legacy, depth + 1, budget))
      }
      let composed = match keyword {
        "allOf" => {
          let mut merged = Any
          for child in children {
            merged = intersect(merged, child, budget)
          }
          merged
        }
        "anyOf" => Union(children)
        _ => ExactlyOne(children)
      }
      result = intersect(result, composed, budget)
    }
  }
  result
}

///|
/// Parse positive compositions, type/enum, object/item and numeric/size assertions.
/// Unsupported assertions return an explicit error, including format/default,
/// multipleOf and directional readOnly/writeOnly annotations.
pub fn parse(
  value : Json,
  openapi_30~ : Bool = false,
) -> Schema raise SchemaError {
  validate_value(value, 0, { remaining: 20000, })
  { model: read_model(value, openapi_30, 0, { remaining: 20000, }), }
}

///|
fn validate_value(
  value : Json,
  depth : Int32,
  budget : Budget,
) -> Unit raise SchemaError {
  consume(budget)
  if depth > 128 {
    raise SchemaError("JSON value depth exceeds 128")
  }
  match value {
    Object(fields) =>
      for (_, value) in fields {
        validate_value(value, depth + 1, budget)
      }
    Array(values) =>
      for value in values {
        validate_value(value, depth + 1, budget)
      }
    Number(number, ..) => {
      if number != number ||
        number > 1.7976931348623157e308 ||
        number < -1.7976931348623157e308 {
        raise SchemaError("Non-finite Schema number")
      }
      let parsed = @json.parse(value.stringify()) catch {
        _ => raise SchemaError("Invalid numeric representation")
      }
      if parsed is Number(n, ..) {
        if n != n || n > 1.7976931348623157e308 || n < -1.7976931348623157e308 {
          raise SchemaError("Non-finite numeric representation")
        }
      } else {
        raise SchemaError("Expected a numeric representation")
      }
    }
    _ => ()
  }
}
