///|
fn compare_schema(
  before : @openapi.SchemaContract?,
  after : @openapi.SchemaContract?,
  before_30 : Bool,
  after_30 : Bool,
  operation : @openapi.OperationContract,
  parameter : String?,
  position : String?,
  request : Bool,
  findings : Array[Finding],
  diagnostics : Array[@openapi.Diagnostic],
  rule_id~ : String? = None,
) -> Unit {
  let at = match after {
    Some(schema) => schema.location
    None => operation.location
  }
  let result = try {
    let old = @schema.parse(
      match before {
        Some(s) => s.definition
        None => Json::object(Map([]))
      },
      openapi_30=before_30,
    )
    let next = @schema.parse(
      match after {
        Some(s) => s.definition
        None => Json::object(Map([]))
      },
      openapi_30=after_30,
    )
    if request {
      @schema.subset(old, next)
    } else {
      @schema.subset(next, old)
    }
  } catch {
    @schema.SchemaError(message) => @schema.Unknown(message)
  }
  match result {
    Included => ()
    Excluded(witness) =>
      findings.push({
        rule_id: rule_id.unwrap_or(
          if request {
            "request-schema-narrowed"
          } else {
            "response-schema-widened"
          },
        ),
        http_method: operation.http_method,
        path: operation.path,
        parameter,
        position,
        message: if request {
          "A previously accepted request value is rejected by the candidate Schema"
        } else {
          "A candidate response value is rejected by the previous Schema"
        },
        location: at,
        witness: Some(witness),
      })
    Unknown(message) =>
      diagnostics.push({ code: "compat.schema", message, location: at, })
  }
}

///|
fn payload_finding(
  rule_id : String,
  message : String,
  at : @openapi.Location,
  operation : @openapi.OperationContract,
  findings : Array[Finding],
  parameter~ : String? = None,
  position~ : String? = None,
) -> Unit {
  findings.push({
    rule_id,
    message,
    location: at,
    http_method: operation.http_method,
    path: operation.path,
    parameter,
    position,
    witness: None,
  })
}

///|
fn compare_content(
  before : Array[@openapi.MediaContract],
  after : Array[@openapi.MediaContract],
  before_30 : Bool,
  after_30 : Bool,
  operation : @openapi.OperationContract,
  context : String,
  request : Bool,
  findings : Array[Finding],
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  if before.any(m => m.media_type.contains("*") || m.media_type.contains(";")) ||
    after.any(m => m.media_type.contains("*") || m.media_type.contains(";")) {
    unsupported(
      diagnostics,
      "Media type wildcards or parameters require range matching",
      operation.location,
    )
    return
  }
  let old = Map([])
  let next = Map([])
  for media in before {
    old[media.media_type] = media
  }
  for media in after {
    next[media.media_type] = media
  }
  let observed = if request { before } else { after }
  for media in observed {
    let target = if request {
      next.get(media.media_type)
    } else {
      old.get(media.media_type)
    }
    if target is None {
      payload_finding(
        if request {
          "request-body-media-type-removed"
        } else {
          "response-media-type-added"
        },
        context + " media type no longer covered: " + media.media_type,
        media.location,
        operation,
        findings,
      )
    }
  }
  for media in after {
    if old.get(media.media_type) is Some(previous) {
      if !previous.same_remainder(media) {
        unsupported(
          diagnostics,
          "Changed media encoding or unevaluated media field",
          media.location,
        )
      }
      compare_schema(
        previous.schema,
        media.schema,
        before_30,
        after_30,
        operation,
        None,
        Some(context + ":" + media.media_type),
        request,
        findings,
        diagnostics,
      )
    }
  }
}

///|
fn compare_payloads(
  before : @openapi.OperationContract,
  after : @openapi.OperationContract,
  before_30 : Bool,
  after_30 : Bool,
  findings : Array[Finding],
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  match (before.request_body, after.request_body) {
    (None, Some(body)) if body.required =>
      payload_finding(
        "request-body-added-required",
        "Previously valid requests can omit the body; the candidate requires it",
        body.location,
        after,
        findings,
      )
    (Some(old), Some(next)) => {
      if !old.required && next.required {
        payload_finding(
          "request-body-became-required",
          "The request body changes from optional to required",
          next.location,
          after,
          findings,
        )
      }
      if !old.same_remainder(next) {
        unsupported(
          diagnostics,
          "Changed unevaluated request body field",
          next.location,
        )
      }
      compare_content(
        old.content,
        next.content,
        before_30,
        after_30,
        after,
        "request-body",
        true,
        findings,
        diagnostics,
      )
    }
    (Some(_), None) =>
      unsupported(diagnostics, "Removed request body contract", after.location)
    _ => ()
  }
  compare_responses(before, after, before_30, after_30, findings, diagnostics)
}
