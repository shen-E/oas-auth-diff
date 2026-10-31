///|
priv struct FormatBudget {
  mut remaining : Int32
}

///|
priv suberror FormatError {
  FormatError(String)
}

///|
fn format_annotations(
  value : Json,
  pointer : String,
  out : Map[String, Map[String, Bool]],
  budget : FormatBudget,
) -> Unit raise FormatError {
  budget.remaining -= 1
  if budget.remaining < 0 {
    raise FormatError("Format annotation traversal exceeds 20000 Schema nodes")
  }
  guard value is Object(fields) else { return }
  if fields.get("format") is Some(String(format)) {
    let values = out.get(pointer).unwrap_or(Map([]))
    values[format] = true
    out[pointer] = values
  }
  for name, child in fields {
    let at = pointer + "/" + name
    if ["properties", "patternProperties", "dependentSchemas"].contains(name) &&
      child is Object(properties) {
      for name, schema in properties {
        format_annotations(
          schema,
          at +
          "/" +
          name.replace_all(old="~", new="~0").replace_all(old="/", new="~1"),
          out,
          budget,
        )
      }
    } else if name == "allOf" && child is Array(children) {
      for schema in children {
        format_annotations(schema, pointer, out, budget)
      }
    } else if ["anyOf", "oneOf", "prefixItems"].contains(name) &&
      child is Array(children) {
      for index, schema in children {
        format_annotations(schema, at + "/" + index.to_string(), out, budget)
      }
    } else if [
        "items", "additionalProperties", "not", "contains", "if", "then", "else",
        "propertyNames", "unevaluatedProperties", "unevaluatedItems",
      ].contains(name) {
      format_annotations(child, at, out, budget)
    }
  }
}

///|
fn format_signature(values : Map[String, Bool]?) -> String {
  match values {
    None => "<absent>"
    Some(values) => {
      let labels = values.keys().collect()
      labels.sort()
      Json(labels).stringify()
    }
  }
}

///|
fn compare_formats(
  before : @openapi.SchemaContract?,
  after : @openapi.SchemaContract?,
  at : @openapi.Location,
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  let old = Map([])
  let next = Map([])
  let budget = { remaining: 20000, }
  try {
    if before is Some(schema) {
      format_annotations(schema.definition, "", old, budget)
    }
    if after is Some(schema) {
      format_annotations(schema.definition, "", next, budget)
    }
  } catch {
    FormatError(message) => {
      diagnostics.push({ code: "resource.formats", message, location: at, })
      return
    }
  }
  let keys = old.keys().collect()
  for key in next.keys() {
    if !old.contains(key) {
      keys.push(key)
    }
  }
  keys.sort()
  for key in keys {
    let before = format_signature(old.get(key))
    let after = format_signature(next.get(key))
    if before != after {
      diagnostics.push({
        code: "compat.format",
        location: at,
        message: "Changed format annotation in resolved Schema at " +
        (if key == "" { "/" } else { key }) +
        ": " +
        before +
        " -> " +
        after +
        "; client/serializer policy is required",
      })
    }
  }
}
