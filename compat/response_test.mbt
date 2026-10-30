///|
fn responses_spec(responses : Json) -> @openapi.Specification raise {
  let document : Json = {
    "openapi": "3.1.1",
    "paths": { "/orders": { "get": { "responses": responses } } },
  }
  @openapi.parse_specification(document.stringify(), format=@openapi.Json)
}

///|
test "explicit success deletion is breaking while additional and error statuses are compatible" {
  let before = responses_spec({
    "200": { "description": "ok" },
    "400": { "description": "bad" },
  })
  let changed = responses_spec({ "201": { "description": "ok" } })
  let report = @compat.compare(before, changed)
  assert_eq(report.exit_code(), 1)
  assert_eq(report.findings.length(), 1)
  assert_eq(report.findings[0].rule_id, "response-success-status-removed")
  assert_eq(report.findings[0].position, Some("response:200"))
  assert_eq(
    @compat.compare(responses_spec({ "200": { "description": "ok" } }), before).exit_code(),
    0,
  )
  assert_eq(
    @compat.compare(before, responses_spec({ "200": { "description": "ok" } })).exit_code(),
    0,
  )
}

///|
test "response headers compare without case and preserve required guarantees" {
  let before = responses_spec({
    "200": {
      "description": "ok",
      "headers": {
        "X-ID": { "required": true, "schema": { "type": "string" } },
        "X-Optional": { "schema": { "type": "string" } },
      },
    },
  })
  let after = responses_spec({
    "200": {
      "description": "edited",
      "headers": {
        "x-id": { "required": false, "schema": { "type": "string" } },
      },
    },
  })
  let changed = @compat.compare(before, after)
  assert_eq(changed.exit_code(), 1)
  assert_eq(changed.findings.length(), 1)
  assert_eq(changed.findings[0].rule_id, "response-header-became-optional")
  assert_eq(changed.findings[0].parameter, Some("x-id"))
  let removed = @compat.compare(
    before,
    responses_spec({ "200": { "description": "ok" } }),
  )
  assert_eq(removed.exit_code(), 1)
  assert_eq(removed.findings.length(), 1)
  assert_eq(removed.findings[0].rule_id, "response-header-required-removed")
}

///|
test "response header widening produces an independently evaluated Schema witness" {
  let before = responses_spec({
    "200": {
      "description": "ok",
      "headers": { "X-State": { "schema": { "enum": ["done"] } } },
    },
  })
  let after = responses_spec({
    "200": {
      "description": "ok",
      "headers": { "x-state": { "schema": { "enum": ["done", "draft"] } } },
    },
  })
  let report = @compat.compare(before, after)
  assert_eq(report.exit_code(), 1)
  assert_eq(report.findings[0].rule_id, "response-header-schema-widened")
  assert_eq(report.findings[0].witness, Some(Json::string("draft")))
  assert_eq(@compat.compare(after, before).exit_code(), 0)
}

///|
test "effective response matching applies exact then range then default and deduplicates ranges" {
  let old_response : Json = {
    "description": "ok",
    "content": { "application/json": { "schema": { "type": "string" } } },
  }
  let new_response : Json = {
    "description": "ok",
    "content": {
      "application/json": { "schema": { "type": ["string", "null"] } },
    },
  }
  let before = responses_spec({ "2XX": old_response, "default": old_response })
  let after = responses_spec({
    "200": old_response,
    "2XX": new_response,
    "default": old_response,
  })
  let result = @compat.compare(before, after)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].position, Some("response:2XX:application/json"))
  assert_eq(result.findings[0].witness, Some(Json::null()))
}
