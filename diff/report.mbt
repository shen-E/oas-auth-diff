///|
fn kind_name(kind : ChangeKind) -> String {
  match kind {
    Equivalent => "equivalent"
    Strengthened => "strengthened"
    Weakened => "weakened"
    Mixed => "mixed"
    Added => "added"
    Removed => "removed"
    Incomparable => "incomparable"
  }
}

///|
fn atom_json(atom : @logic.Atom) -> Json {
  match atom {
    Credential(scheme) => { "kind": "credential", "scheme": scheme }
    Scope(scheme, name) => { "kind": "scope", "scheme": scheme, "name": name }
    Role(scheme, name) => { "kind": "role", "scheme": scheme, "name": name }
  }
}

///|
fn policy_json(policy : @logic.Policy?) -> Json {
  match policy {
    None => Json::null()
    Some(policy) =>
      Json(policy.alternatives().map(fn(atoms) { Json(atoms.map(atom_json)) }))
  }
}

///|
fn witness_json(witness : @logic.GrantSet?) -> Json {
  match witness {
    None => Json::null()
    Some(grants) => Json(grants.atoms().map(atom_json))
  }
}

///|
fn location_json(location : @openapi.Location) -> Json {
  { "uri": location.uri, "pointer": location.pointer }
}

///|
fn diagnostic_json(diagnostic : @openapi.Diagnostic) -> Json {
  {
    "code": diagnostic.code,
    "message": diagnostic.message,
    "location": location_json(diagnostic.location),
  }
}

///|
fn added_anonymous(change : OperationChange) -> Bool {
  change.kind == Added &&
  (match change.after {
    Some(policy) => policy.allows(@logic.GrantSet::new([]))
    None => false
  })
}

///|
fn change_json(change : OperationChange) -> Json {
  {
    "method": change.http_method,
    "path": change.path,
    "before_path": match change.before_path {
      Some(path) => Json(path)
      None => Json::null()
    },
    "after_path": match change.after_path {
      Some(path) => Json(path)
      None => Json::null()
    },
    "operation_id": match change.operation_id {
      Some(value) => Json(value)
      None => Json::null()
    },
    "kind": kind_name(change.kind),
    "before": policy_json(change.before),
    "after": policy_json(change.after),
    "witness": witness_json(change.witness),
    "review_anonymous": added_anonymous(change),
    "location": location_json(change.location),
  }
}

///|
fn document_urls(comparison : Comparison) -> Json {
  {
    "before": match comparison.before_document_url {
      Some(url) => Json(url)
      None => Json::null()
    },
    "after": match comparison.after_document_url {
      Some(url) => Json(url)
      None => Json::null()
    },
  }
}

///|
fn document_sources(comparison : Comparison) -> Json {
  {
    "before": match comparison.before_source {
      Some(source) => Json(source)
      None => Json::null()
    },
    "after": match comparison.after_source {
      Some(source) => Json(source)
      None => Json::null()
    },
  }
}

///|
/// Render a stable, versioned JSON report, including incomplete results.
pub fn render_json(comparison : Comparison) -> String {
  let report : Json = {
    "schema_version": 1,
    "complete": comparison.complete,
    "exit_code": comparison.exit_code(),
    "document_urls": document_urls(comparison),
    "document_sources": document_sources(comparison),
    "changes": Json(comparison.changes.map(change_json)),
    "diagnostics": Json(comparison.diagnostics.map(diagnostic_json)),
  }
  report.stringify(indent=2)
}

///|
fn atom_text(atom : @logic.Atom) -> String {
  match atom {
    Credential(scheme) => "credential(\{scheme})"
    Scope(scheme, name) => "scope(\{scheme}, \{name})"
    Role(scheme, name) => "role(\{scheme}, \{name})"
  }
}

///|
fn grants_text(grants : @logic.GrantSet) -> String {
  if grants.atoms().is_empty() {
    "anonymous (no credentials)"
  } else {
    grants.atoms().map(atom_text).join(", ")
  }
}

///|
fn change_path(change : OperationChange) -> String {
  match (change.before_path, change.after_path) {
    (Some(before), Some(after)) if before != after => before + " -> " + after
    _ => change.path
  }
}

///|
pub fn render_text(comparison : Comparison) -> String {
  let lines = [
    "oas-auth-diff: \{if comparison.complete { "complete" } else { "incomplete" }}",
  ]
  if comparison.before_document_url is Some(url) {
    lines.push("Baseline document URL: " + url)
  }
  if comparison.after_document_url is Some(url) {
    lines.push("Candidate document URL: " + url)
  }
  for change in comparison.changes {
    let review = if added_anonymous(change) {
      " (anonymous operation; review)"
    } else {
      ""
    }
    lines.push(
      "\{change.http_method} \{change_path(change)}: \{kind_name(change.kind)}\{review}",
    )
    if change.witness is Some(grants) {
      lines.push("  new allows, old rejects: \{grants_text(grants)}")
    }
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
fn sarif_location(
  location : @openapi.Location,
  source_root : SarifSourceRoot?,
) -> Json {
  let valid_uri = sarif_uri(location.uri)
  if valid_uri {
    let artifact : Json = match source_root {
      Some(root) =>
        match sarif_relative_uri(location.uri, root) {
          Some(uri) => { "uri": uri, "uriBaseId": "%SRCROOT%" }
          None => { "uri": location.uri }
        }
      None => { "uri": location.uri }
    }
    {
      "physicalLocation": { "artifactLocation": artifact },
      "properties": { "source": location.uri, "jsonPointer": location.pointer },
    }
  } else {
    {
      "logicalLocations": [
        { "fullyQualifiedName": "\{location.uri}#\{location.pointer}" },
      ],
      "properties": { "source": location.uri, "jsonPointer": location.pointer },
    }
  }
}

///|
// Library callers may use labels such as <input> instead of source URIs.
// Only emit a physical location for an absolute URI with valid ASCII escapes.
fn sarif_uri(value : String) -> Bool {
  let parts = value.split(":").to_array()
  if parts.length() < 2 || parts[0].is_empty() {
    return false
  }
  let scheme = parts[0].to_array()
  if !uri_alpha(scheme[0]) ||
    !scheme.all(fn(c) {
      uri_alpha(c) ||
      (match c {
        '0'..<='9' | '+' | '-' | '.' => true
        _ => false
      })
    }) {
    return false
  }
  let chars = value.to_array()
  let mut index = 0
  while index < chars.length() {
    let char = chars[index]
    if char == '%' {
      if index + 2 >= chars.length() ||
        !uri_hex(chars[index + 1]) ||
        !uri_hex(chars[index + 2]) {
        return false
      }
      index += 3
    } else if uri_char(char) {
      index += 1
    } else {
      return false
    }
  }
  true
}

///|
fn uri_alpha(char : Char) -> Bool {
  match char {
    'a'..<='z' | 'A'..<='Z' => true
    _ => false
  }
}

///|
fn uri_hex(char : Char) -> Bool {
  match char {
    '0'..<='9' | 'a'..<='f' | 'A'..<='F' => true
    _ => false
  }
}

///|
fn uri_char(char : Char) -> Bool {
  uri_alpha(char) ||
  (match char {
    '0'..<='9'
    | '-'
    | '.'
    | '_'
    | '~'
    | ':'
    | '/'
    | '?'
    | '#'
    | '['
    | ']'
    | '@'
    | '!'
    | '$'
    | '&'
    | '\''
    | '('
    | ')'
    | '*'
    | '+'
    | ','
    | ';'
    | '=' => true
    _ => false
  })
}

///|
fn route_fingerprint(
  comparison : Comparison,
  change : OperationChange,
  rule : String,
  source_root : SarifSourceRoot?,
) -> String? {
  let source = match comparison.after_source {
    Some(source) =>
      match sarif_file_identity(source) {
        Some(source) => source
        None => return None
      }
    _ => return None
  }
  let shape = match @openapi.path_identity(change.path) {
    Some(shape) => shape
    None => return None
  }
  let entry_identity = match source_root {
    Some(root) =>
      match sarif_relative_uri(source, root) {
        Some(relative) => "relative:" + relative
        None => "absolute:" + source
      }
    None => "absolute:" + source
  }
  let input : Json = [
    "oas-auth-diff/route/v1",
    rule,
    entry_identity,
    change.http_method,
    shape,
  ]
  Some(
    @crypto.bytes_to_hex_string(@crypto.sha256(@utf8.encode(input.stringify()))),
  )
}

///|
/// SARIF stores JSON Pointers without inventing source line numbers.
pub fn render_sarif(
  comparison : Comparison,
  source_root~ : SarifSourceRoot? = None,
) -> String {
  let results : Array[Json] = []
  for change in comparison.changes {
    let regression = change.kind == Weakened || change.kind == Mixed
    if regression || added_anonymous(change) {
      let message = if regression {
        let grants = change.witness.map(grants_text).unwrap_or("unavailable")
        "\{change.http_method} \{change_path(change)}: \{kind_name(change.kind)}; new allows, old rejects: \{grants}"
      } else {
        "\{change.http_method} \{change.path}: added anonymous operation; review access requirements"
      }
      let rule = if regression { "auth-regression" } else { "added-anonymous" }
      let result : Map[String, Json] = {
        "ruleId": Json(rule),
        "level": if regression {
          "error"
        } else {
          "note"
        },
        "message": { "text": message },
        "locations": [sarif_location(change.location, source_root)],
        "properties": change_json(change),
      }
      if route_fingerprint(comparison, change, rule, source_root)
        is Some(fingerprint) {
        result["partialFingerprints"] = {
          "oasAuthDiff/route/v1": fingerprint,
          "primaryLocationLineHash": fingerprint,
        }
      }
      results.push(Json::object(result))
    }
  }
  let notifications : Array[Json] = comparison.diagnostics.map(fn(diagnostic) {
    {
      "descriptor": { "id": diagnostic.code },
      "level": "error",
      "message": { "text": diagnostic.message },
      "locations": [sarif_location(diagnostic.location, source_root)],
    }
  })
  let invocation : Map[String, Json] = {
    "executionSuccessful": Json(comparison.complete),
    "exitCode": Json(comparison.exit_code()),
    "toolExecutionNotifications": Json(notifications),
  }
  if source_root is Some(root) {
    invocation["workingDirectory"] = { "uri": root.uri() }
  }
  let run : Map[String, Json] = {
    "tool": {
      "driver": {
        "name": "oas-auth-diff",
        "version": "0.8.0",
        "informationUri": "https://github.com/shen-E/oas-auth-diff",
        "rules": [
          {
            "id": "auth-regression",
            "shortDescription": {
              "text": "Authentication requirements admit new access conditions",
            },
          },
          {
            "id": "added-anonymous",
            "shortDescription": {
              "text": "New anonymous operation requires review",
            },
          },
        ],
      },
    },
    "results": Json(results),
    "invocations": Json([Json::object(invocation)]),
    "properties": {
      "schema_version": 1,
      "complete": comparison.complete,
      "document_urls": document_urls(comparison),
      "document_sources": document_sources(comparison),
      "changes": Json(comparison.changes.map(change_json)),
    },
  }
  if source_root is Some(root) {
    run["originalUriBaseIds"] = { "%SRCROOT%": { "uri": root.uri() } }
  }
  let report : Json = {
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    "version": "2.1.0",
    "runs": Json([Json::object(run)]),
  }
  report.stringify(indent=2)
}
