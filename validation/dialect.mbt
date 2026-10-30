///|
fn dialect_overrides(
  value : Json,
  at : @openapi.Location,
  schema : Bool,
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  match value {
    Object(fields) => {
      if schema &&
        fields.get("$schema") is Some(String(uri)) &&
        uri != "https://spec.openapis.org/oas/3.1/dialect/2024-11-10" {
        diagnostics.push({
          code: "validation.dialect",
          message: "Schema dialect override is not bundled: " + uri,
          location: { uri: at.uri, pointer: at.pointer + "/$schema", },
        })
      }
      for (key, child) in fields {
        let child_at = location_key(at, key)
        if schema {
          if ["properties", "patternProperties", "$defs", "dependentSchemas"].contains(
              key,
            ) &&
            child is Object(children) {
            for (name, schema) in children {
              dialect_overrides(
                schema,
                location_key(child_at, name),
                true,
                diagnostics,
              )
            }
          } else if [
              "allOf", "anyOf", "oneOf", "prefixItems", "items", "additionalProperties",
              "not", "contains", "if", "then", "else", "propertyNames", "unevaluatedProperties",
              "unevaluatedItems",
            ].contains(key) {
            dialect_overrides(child, child_at, true, diagnostics)
          }
          continue
        }
        if ["example", "examples", "default", "enum", "const"].contains(key) ||
          key.has_prefix("x-") {
          continue
        }
        let pointer = at.pointer +
          "/" +
          key.replace_all(old="~", new="~0").replace_all(old="/", new="~1")
        if key == "schemas" &&
          at.pointer == "/components" &&
          child is Object(schemas) {
          for (name, schema) in schemas {
            dialect_overrides(
              schema,
              location_key(child_at, name),
              true,
              diagnostics,
            )
          }
        } else {
          dialect_overrides(
            child,
            { uri: at.uri, pointer, },
            key == "schema",
            diagnostics,
          )
        }
      }
    }
    Array(values) =>
      for index, value in values {
        dialect_overrides(
          value,
          { uri: at.uri, pointer: at.pointer + "/" + index.to_string(), },
          schema,
          diagnostics,
        )
      }
    _ => ()
  }
}
