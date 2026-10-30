///|
fn response_for(
  responses : Map[String, @openapi.ResponseContract],
  status : String,
) -> @openapi.ResponseContract? {
  match responses.get(status) {
    Some(response) => Some(response)
    None =>
      match responses.get(status[0:1].to_owned() + "XX") {
        Some(response) => Some(response)
        None => responses.get("default")
      }
  }
}

///|
fn compare_headers(
  before : @openapi.ResponseContract,
  after : @openapi.ResponseContract,
  before_30 : Bool,
  after_30 : Bool,
  operation : @openapi.OperationContract,
  context : String,
  findings : Array[Finding],
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  let current = Map([])
  for header in after.headers {
    current[header.name.to_lower()] = header
  }
  for previous in before.headers {
    let name = previous.name.to_lower()
    let position = Some("response:" + context + ":header")
    match current.get(name) {
      None if previous.required =>
        payload_finding(
          "response-header-required-removed",
          "Previously guaranteed response header removed: " + previous.name,
          previous.location,
          operation,
          findings,
          parameter=Some(name),
          position~,
        )
      Some(next) => {
        if previous.required && !next.required {
          payload_finding(
            "response-header-became-optional",
            "Response header is no longer guaranteed: " + next.name,
            next.location,
            operation,
            findings,
            parameter=Some(name),
            position~,
          )
        }
        if !previous.same_remainder(next) {
          unsupported(
            diagnostics,
            "Changed response header serialization: " + next.name,
            next.location,
          )
        }
        if previous.content.is_empty() && next.content.is_empty() {
          compare_schema(
            previous.schema,
            next.schema,
            before_30,
            after_30,
            operation,
            Some(name),
            position,
            false,
            findings,
            diagnostics,
            rule_id=Some("response-header-schema-widened"),
          )
        } else if previous.content.is_empty() || next.content.is_empty() {
          unsupported(
            diagnostics,
            "Response header changes between schema and content serialization: " +
            next.name,
            next.location,
          )
        } else {
          compare_content(
            previous.content,
            next.content,
            before_30,
            after_30,
            operation,
            "response-header:" + context + ":" + name,
            false,
            findings,
            diagnostics,
          )
        }
      }
      _ => ()
    }
  }
}

///|
fn compare_responses(
  before : @openapi.OperationContract,
  after : @openapi.OperationContract,
  before_30 : Bool,
  after_30 : Bool,
  findings : Array[Finding],
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  let old = Map([])
  let next = Map([])
  for response in before.responses {
    old[response.status] = response
  }
  for response in after.responses {
    next[response.status] = response
  }
  for response in before.responses {
    if response.status.has_prefix("2") &&
      !response.status.contains("X") &&
      !next.contains(response.status) {
      payload_finding(
        "response-success-status-removed",
        "Explicit successful response status removed: " + response.status,
        response.location,
        after,
        findings,
        position=Some("response:" + response.status),
      )
    }
  }
  // Evaluate the effective response with exact > range > default precedence.
  // Compare each declaration pair once even when it covers many HTTP codes.
  let visited = Map([])
  for code in 100..<600 {
    let status = code.to_string()
    if response_for(old, status) is Some(previous) &&
      response_for(next, status) is Some(response) {
      let key = (previous.status, response.status)
      if visited.contains(key) {
        continue
      }
      visited[key] = true
      let context = if previous.status == response.status {
        response.status
      } else {
        previous.status + "->" + response.status
      }
      if !previous.same_remainder(response) {
        unsupported(
          diagnostics,
          "Changed response links or other unevaluated field",
          response.location,
        )
      }
      compare_content(
        previous.content,
        response.content,
        before_30,
        after_30,
        after,
        "response:" + context,
        false,
        findings,
        diagnostics,
      )
      compare_headers(
        previous, response, before_30, after_30, after, context, findings, diagnostics,
      )
    }
  }
}
