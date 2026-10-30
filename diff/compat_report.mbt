///|
/// Render the bounded endpoint/parameter compatibility profile as JSON.
pub fn render_compatibility_json(comparison : @compat.Comparison) -> String {
  let report : Json = {
    "schema_version": 1,
    "report_kind": "compatibility",
    "scope": "endpoint-removal-and-required-parameters",
    "checked_rules": Json(@compat.checks()),
    "complete": comparison.complete,
    "exit_code": comparison.exit_code(),
    "document_sources": {
      "before": comparison.before_source,
      "after": comparison.after_source,
    },
    "findings": Json(comparison.findings),
    "diagnostics": Json(comparison.diagnostics),
  }
  report.stringify(indent=2)
}

///|
pub fn render_compatibility_text(comparison : @compat.Comparison) -> String {
  let lines = [
    "oas-auth-diff: compatibility " +
    (if comparison.complete { "complete" } else { "incomplete" }),
    "Profile: endpoint removal and required request parameters (3 checks)",
    "Other changed contract fields are not classified; they make analysis incomplete.",
  ]
  for finding in comparison.findings {
    lines.push(
      "\{finding.http_method} \{finding.path}: \{finding.rule_id}: \{finding.message}",
    )
  }
  for diagnostic in comparison.diagnostics {
    lines.push(
      "\{diagnostic.location.uri}#\{diagnostic.location.pointer}: \{diagnostic.code}: \{diagnostic.message}",
    )
  }
  lines.push("exit code: \{comparison.exit_code()}")
  lines.join("\n")
}

///|
pub fn render_compatibility_sarif(
  comparison : @compat.Comparison,
  source_root~ : SarifSourceRoot? = None,
) -> String {
  let results = comparison.findings.map(finding => {
    let source = match source_root {
      Some(root) =>
        sarif_relative_uri(comparison.after_source, root).unwrap_or(
          comparison.after_source,
        )
      None => comparison.after_source
    }
    let key : Json = [
      "oas-auth-diff/compatibility/v1",
      source,
      finding.rule_id,
      finding.http_method,
      @openapi.path_identity(finding.path).unwrap_or(finding.path),
      finding.position.unwrap_or(""),
      if finding.position == Some("header") {
        finding.parameter.unwrap_or("").to_lower()
      } else {
        finding.parameter.unwrap_or("")
      },
    ]
    let fingerprint = @crypto.bytes_to_hex_string(
      @crypto.sha256(@utf8.encode(key.stringify())),
    )
    let result : Json = {
      "ruleId": finding.rule_id,
      "level": "error",
      "message": { "text": finding.message },
      "locations": [sarif_location(finding.location, source_root)],
      "partialFingerprints": { "compatibility/v1": fingerprint },
      "properties": { "method": finding.http_method, "path": finding.path },
    }
    result
  })
  let notifications = comparison.diagnostics.map(diagnostic => {
    let notification : Json = {
      "level": "error",
      "descriptor": { "id": diagnostic.code },
      "message": { "text": diagnostic.message },
      "locations": [sarif_location(diagnostic.location, source_root)],
    }
    notification
  })
  let run : Map[String, Json] = Map([
    (
      "tool",
      {
        "driver": {
          "name": "oas-auth-diff",
          "rules": Json(
            @compat.checks().map(id => {
              let rule : Json = { "id": id }
              rule
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
          "executionSuccessful": comparison.complete,
          "toolExecutionNotifications": Json(notifications),
        },
      ],
    ),
    (
      "properties",
      {
        "report_kind": "compatibility",
        "scope": "endpoint-removal-and-required-parameters",
        "checked_rules": Json(@compat.checks()),
      },
    ),
  ])
  if source_root is Some(root) {
    run["originalUriBaseIds"] = { "%SRCROOT%": { "uri": root.uri() } }
  }
  let report : Json = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [Json::object(run)],
  }
  report.stringify(indent=2)
}
