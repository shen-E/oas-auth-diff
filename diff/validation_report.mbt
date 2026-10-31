///|
pub fn render_validation_sarif(
  report : @validation.Report,
  source_root~ : SarifSourceRoot? = None,
) -> String {
  let rules = Map([])
  let results : Array[Json] = []
  for violation in report.violations {
    let rule = "openapi-" + violation.keyword
    rules[rule] = true
    let source = match source_root {
      Some(root) =>
        sarif_relative_uri(violation.location.uri, root).unwrap_or(
          violation.location.uri,
        )
      None => violation.location.uri
    }
    let key : Json = [
      "oas-auth-diff/validation/v1",
      source,
      rule,
      violation.location.pointer,
      violation.schema_pointer,
    ]
    let fingerprint = @crypto.bytes_to_hex_string(
      @crypto.sha256(@utf8.encode(key.stringify())),
    )
    results.push({
      "ruleId": rule,
      "level": "error",
      "message": { "text": violation.message },
      "locations": [sarif_location(violation.location, source_root)],
      "partialFingerprints": { "validation/v1": fingerprint },
      "properties": {
        "metaschema": report.metaschema,
        "schema_pointer": violation.schema_pointer,
      },
    })
  }
  let ids = rules.keys().collect()
  ids.sort()
  let run : Map[String, Json] = Map([
    (
      "tool",
      {
        "driver": {
          "name": "oas-auth-diff",
          "rules": Json(
            ids.map(id => {
              let value : Json = { "id": id }
              value
            }),
          ),
        },
      },
    ),
    ("results", Json(results)),
    (
      "invocations",
      [
        {
          "executionSuccessful": report.complete,
          "toolExecutionNotifications": Json(
            report.diagnostics.map(d => {
              let value : Json = {
                "level": "error",
                "descriptor": { "id": d.code },
                "message": { "text": d.message },
                "locations": [sarif_location(d.location, source_root)],
              }
              value
            }),
          ),
        },
      ],
    ),
    (
      "properties",
      {
        "report_kind": "validation",
        "scope": "official-document-and-reference-targets",
        "reference_targets_checked": report.complete,
        "format_assertions": false,
        "metaschema": report.metaschema,
      },
    ),
  ])
  if source_root is Some(root) {
    run["originalUriBaseIds"] = { "%SRCROOT%": { "uri": root.uri() } }
  }
  let value : Json = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [Json::object(run)],
  }
  value.stringify(indent=2)
}
