///|
pub(all) struct Violation {
  keyword : String
  message : String
  location : @openapi.Location
  schema_pointer : String
} derive(Debug, ToJson)

///|
pub extend Violation with Debug::{to_repr}

///|
pub extend Violation with ToJson::{to_json}

///|
pub(all) struct Report {
  source : String
  openapi_version : String
  metaschema : String
  violations : Array[Violation]
  diagnostics : Array[@openapi.Diagnostic]
  complete : Bool
}

///|
pub fn Report::exit_code(self : Report) -> Int32 {
  if !self.complete {
    2
  } else if self.violations.is_empty() {
    0
  } else {
    1
  }
}

///|
pub fn render_json(report : Report) -> String {
  let value : Json = {
    "schema_version": 1,
    "report_kind": "validation",
    "scope": "official-entry-document-metaschema",
    "reference_targets_checked": false,
    "format_assertions": false,
    "complete": report.complete,
    "valid": if report.complete {
      Json::boolean(report.violations.is_empty())
    } else {
      Json::null()
    },
    "exit_code": report.exit_code(),
    "source": report.source,
    "openapi_version": report.openapi_version,
    "metaschema": report.metaschema,
    "violations": Json(report.violations),
    "diagnostics": Json(report.diagnostics),
  }
  value.stringify(indent=2)
}

///|
pub fn render_text(report : Report) -> String {
  let lines = [
    "oas-auth-diff: OpenAPI entry-document validation " +
    (if !report.complete {
      "incomplete"
    } else if report.violations.is_empty() {
      "passed"
    } else {
      "failed"
    }),
    "Metaschema: " + report.metaschema,
  ]
  for violation in report.violations {
    lines.push(
      violation.location.uri +
      "#" +
      violation.location.pointer +
      ": " +
      violation.keyword +
      ": " +
      violation.message,
    )
  }
  for diagnostic in report.diagnostics {
    lines.push(
      diagnostic.location.uri +
      "#" +
      diagnostic.location.pointer +
      ": " +
      diagnostic.code +
      ": " +
      diagnostic.message,
    )
  }
  lines.push("exit code: " + report.exit_code().to_string())
  lines.join("\n")
}

///|
/// Validate the entry document with bundled official OpenAPI metaschemas.
/// Input references remain data; this does not fetch or validate their targets.
pub fn validate(
  text : String,
  format~ : @openapi.InputFormat,
  source~ : String = "<input>",
) -> Report raise @openapi.DocumentError {
  let snapshot = @openapi.parse_snapshot(text, format~, source~)
  let legacy = snapshot.version.has_prefix("3.0.")
  let uri = if legacy {
    "https://spec.openapis.org/oas/3.0/schema/2024-10-18"
  } else {
    "https://spec.openapis.org/oas/3.1/schema-base/2025-09-15"
  }
  let resources = Map([])
  for (key, value) in bundled_schemas {
    resources[key] = engine_schema(
      @json.parse(value) catch {
        _ => raise @openapi.DocumentError("Invalid bundled metaschema: " + key)
      },
    )
  }
  let validator = @metaschema.Schema::new(resources[uri], remotes=resources) catch {
    error =>
      raise @openapi.DocumentError(
        "Cannot initialize bundled metaschema: " + error.to_string(),
      )
  }
  let document = snapshot.to_json()
  let diagnostics : Array[@openapi.Diagnostic] = []
  if !legacy && document is Object(fields) {
    if fields.get("jsonSchemaDialect") is Some(String(dialect)) &&
      dialect != "https://spec.openapis.org/oas/3.1/dialect/2024-11-10" {
      diagnostics.push({
        code: "validation.dialect",
        message: "Custom JSON Schema dialect is not bundled: " + dialect,
        location: { uri: source, pointer: "/jsonSchemaDialect", },
      })
    }
  }
  if !legacy {
    dialect_overrides(
      document,
      { uri: source, pointer: "", },
      false,
      diagnostics,
    )
  }
  let violations : Array[Violation] = []
  if diagnostics.is_empty() {
    let faults = validator.faults(document)
    for index, fault in faults {
      if index >= 1000 {
        diagnostics.push({
          code: "resource.validation-results",
          message: "Validation exceeds 1000 reported violations",
          location: { uri: source, pointer: "", },
        })
        break
      }
      violations.push({
        keyword: fault.keyword,
        message: fault.message,
        location: { uri: source, pointer: fault.at, },
        schema_pointer: fault.schema_at,
      })
    }
    semantic_checks(document, source, violations)
    if violations.length() > 1000 {
      if !diagnostics.any(d => d.code == "resource.validation-results") {
        diagnostics.push({
          code: "resource.validation-results",
          message: "Validation exceeds 1000 reported violations",
          location: { uri: source, pointer: "", },
        })
      }
      while violations.length() > 1000 {
        ignore(violations.pop())
      }
    }
  }
  violations.sort_by((a, b) => {
    (a.location.pointer, a.keyword, a.schema_pointer).compare(
      (b.location.pointer, b.keyword, b.schema_pointer),
    )
  })
  {
    source,
    openapi_version: snapshot.version,
    metaschema: uri,
    violations,
    diagnostics,
    complete: diagnostics.is_empty(),
  }
}
