///|
fn prepare_dialects(
  resources : Map[String, Json],
  supplied : Map[String, Json],
  source : String,
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  let vocabularies = [
    "core", "applicator", "unevaluated", "validation", "meta-data", "format-annotation",
    "content",
  ].map(name => "https://json-schema.org/draft/2020-12/vocab/" + name)
  let validator = @metaschema.Schema::new(
    resources["https://json-schema.org/draft/2020-12/schema"],
    remotes=resources,
  ) catch {
    _ => abort("bundled JSON Schema metaschema must initialize")
  }
  let keys = supplied.keys().collect()
  keys.sort()
  if keys.length() > 64 {
    diagnostics.push({
      code: "resource.dialects",
      message: "Dialect registry exceeds 64 supplied resources",
      location: { uri: source, pointer: "", },
    })
    return
  }
  let budget = { remaining: 20000, }
  for uri in keys {
    let resource = supplied[uri]
    let mut reason = None
    if resources.contains(uri) {
      reason = Some("Cannot replace a bundled metaschema")
    } else if !bounded_dialect(resource, 0, budget) {
      reason = Some("Dialect registry exceeds depth 128 or 20000 JSON nodes")
    } else if resource is Object(fields) {
      if fields.get("$id") != Some(Json::string(uri)) ||
        fields.get("$schema") !=
        Some(Json::string("https://json-schema.org/draft/2020-12/schema")) {
        reason = Some(
          "Supplied dialect must have its registered $id and the 2020-12 $schema",
        )
      } else if dialect_references(resource, true) is Some(message) {
        reason = Some(message)
      } else if !validator.valid(resource) {
        reason = Some("Supplied dialect is not a valid 2020-12 metaschema")
      } else if fields.get("$vocabulary") is Some(Object(declared)) {
        let vocabularies_declared = declared.keys().collect()
        vocabularies_declared.sort()
        for vocabulary in vocabularies_declared {
          let required = declared[vocabulary]
          if required is True &&
            !vocabularies.contains(vocabulary) &&
            vocabulary != "https://spec.openapis.org/oas/3.1/vocab/base" {
            reason = Some(
              "Required vocabulary is not implemented: " + vocabulary,
            )
          }
        }
      }
    } else {
      reason = Some("Supplied dialect must be an object")
    }
    match reason {
      Some(message) =>
        diagnostics.push({
          code: "validation.dialect",
          message: uri + ": " + message,
          location: { uri: source, pointer: "", },
        })
      None => resources[uri] = engine_schema(resource)
    }
  }
}

///|
priv struct DialectBudget {
  mut remaining : Int32
}

///|
fn bounded_dialect(value : Json, depth : Int32, budget : DialectBudget) -> Bool {
  budget.remaining -= 1
  if depth > 128 || budget.remaining < 0 {
    return false
  }
  match value {
    Object(fields) =>
      fields.values().all(value => bounded_dialect(value, depth + 1, budget))
    Array(values) =>
      values.all(value => bounded_dialect(value, depth + 1, budget))
    Number(n, ..) =>
      n == n && n <= 1.7976931348623157e308 && n >= -1.7976931348623157e308
    _ => true
  }
}

///|
// Supplied dialects can extend a bundled metaschema with ordinary assertions.
// Restrict their own references to bundled resources: an arbitrary self-ref
// metaschema can recurse without consuming any part of the input instance.
fn dialect_references(value : Json, root : Bool) -> String? {
  if value is Object(fields) {
    if (!root && fields.contains("$id")) ||
      fields.contains("$dynamicRef") ||
      fields.contains("$recursiveRef") {
      return Some(
        "Supplied dialect resource scopes and dynamic references are unsupported",
      )
    }
    if fields.get("$ref") is Some(String(reference)) {
      if !bundled_schemas
        .keys()
        .any(uri => reference == uri || reference.has_prefix(uri + "#")) {
        return Some(
          "Supplied dialect references must target a bundled metaschema",
        )
      }
    }
    for name, child in fields {
      let kind = child_kind("schema", name)
      if kind.has_prefix("map:") && child is Object(children) {
        for child in children.values() {
          if dialect_references(child, false) is Some(message) {
            return Some(message)
          }
        }
      } else if kind.has_prefix("list:") && child is Array(children) {
        for child in children {
          if dialect_references(child, false) is Some(message) {
            return Some(message)
          }
        }
      } else if kind == "schema" &&
        dialect_references(child, false) is Some(message) {
        return Some(message)
      }
    }
  }
  None
}
