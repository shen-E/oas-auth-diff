///|
fn body_spec(
  schema : Json,
  response~ : Bool = false,
  version~ : String = "3.1.1",
  required~ : Bool = false,
) -> @openapi.Specification raise {
  let operation : Json = if response {
    {
      "responses": {
        "200": {
          "description": "ok",
          "content": { "application/json": { "schema": schema } },
        },
      },
    }
  } else {
    {
      "requestBody": {
        "required": required,
        "content": { "application/json": { "schema": schema } },
      },
    }
  }
  let doc : Json = {
    "openapi": version,
    "paths": { "/orders": { "post": operation } },
  }
  @openapi.parse_specification(doc.stringify(), format=@openapi.Json)
}

///|
test "custom global dialects withdraw Schema conclusions even when unchanged" {
  let original = body_spec({ "type": "integer", "minimum": 1 }).to_json()
  let fields = match original {
    Object(fields) => fields
    _ => fail("expected object")
  }
  fields["jsonSchemaDialect"] = Json::string("https://example.test/custom")
  let custom = @openapi.parse_specification(
    Json::object(fields).stringify(),
    format=@openapi.Json,
  )
  let comparison = @compat.compare(custom, custom)
  assert_eq(comparison.exit_code(), 2)
  assert_true(comparison.findings.is_empty())
  assert_true(comparison.diagnostics.any(d => d.code == "contract.dialect"))
  let supported = body_spec({
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "integer",
    "minimum": 1,
  })
  assert_eq(@compat.compare(supported, supported).exit_code(), 0)
}

///|
test "the same enum change narrows requests but widens responses in reverse" {
  let wide : Json = { "type": "string", "enum": ["read", "write"] }
  let narrow : Json = { "type": "string", "enum": ["read"] }
  let request = @compat.compare(body_spec(wide), body_spec(narrow))
  assert_eq(request.exit_code(), 1)
  assert_eq(request.findings[0].rule_id, "request-schema-narrowed")
  assert_eq(request.findings[0].witness, Some(Json::string("write")))
  assert_eq(@compat.compare(body_spec(narrow), body_spec(wide)).exit_code(), 0)
  let response = @compat.compare(
    body_spec(narrow, response=true),
    body_spec(wide, response=true),
  )
  assert_eq(response.exit_code(), 1)
  assert_eq(response.findings[0].rule_id, "response-schema-widened")
  assert_eq(
    @compat.compare(
      body_spec(wide, response=true),
      body_spec(narrow, response=true),
    ).exit_code(),
    0,
  )
}

///|
test "required object fields and request body requiredness are classified" {
  let optional : Json = {
    "type": "object",
    "properties": { "id": { "type": "integer" } },
  }
  let required : Json = {
    "type": "object",
    "properties": { "id": { "type": "integer" } },
    "required": ["id"],
  }
  assert_eq(
    @compat.compare(body_spec(optional), body_spec(required)).exit_code(),
    1,
  )
  assert_eq(
    @compat.compare(
      body_spec(required, response=true),
      body_spec(optional, response=true),
    ).exit_code(),
    1,
  )
  let changed = @compat.compare(
    body_spec(optional),
    body_spec(optional, required=true),
  )
  assert_eq(changed.exit_code(), 1)
  assert_eq(changed.findings[0].rule_id, "request-body-became-required")
}

///|
test "referenced payload schemas preserve origins and detect shared component changes" {
  let text =
    #|{"openapi":"3.1.1","components":{"schemas":{"Order":{"type":"string","enum":["read","write"]}}},"paths":{"/orders":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}}}}}}
  let before = @openapi.parse_specification(text, format=@openapi.Json)
  let after = @openapi.parse_specification(
    text.replace_all(old="[\"read\",\"write\"]", new="[\"read\"]"),
    format=@openapi.Json,
  )
  let result = @compat.compare(before, after)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.findings[0].location.pointer, "/components/schemas/Order")
}

///|
test "annotations and set ordering preserve compatibility but unknown assertions do not" {
  assert_eq(
    @compat.compare(
      body_spec({ "type": "string", "enum": ["a", "b"] }),
      body_spec({
        "enum": ["b", "a"],
        "type": "string",
        "description": "edited",
      }),
    ).exit_code(),
    0,
  )
  assert_eq(
    @compat.compare(
      body_spec({ "type": "integer", "multipleOf": 1 }),
      body_spec({ "type": "integer", "multipleOf": 2 }),
    ).exit_code(),
    2,
  )
  assert_eq(
    @compat.compare(
      body_spec({ "type": "string", "nullable": true }, version="3.0.3"),
      body_spec({ "type": "string" }, version="3.0.3"),
    ).exit_code(),
    1,
  )
}

///|
test "media matching ignores case, classifies coverage loss and rejects ranges" {
  let text =
    #|{"openapi":"3.1.1","paths":{"/orders":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"string"}}}},"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"string"}}}}}}}}}
  let baseline = @openapi.parse_specification(text, format=@openapi.Json)
  let same = @openapi.parse_specification(
    text.replace_all(old="application/json", new="Application/JSON"),
    format=@openapi.Json,
  )
  assert_eq(@compat.compare(baseline, same).exit_code(), 0)
  let changed = @openapi.parse_specification(
    text.replace_all(old="application/json", new="application/xml"),
    format=@openapi.Json,
  )
  let result = @compat.compare(baseline, changed)
  assert_eq(result.exit_code(), 1)
  assert_true(
    result.findings.any(f => f.rule_id == "request-body-media-type-removed"),
  )
  assert_true(
    result.findings.any(f => f.rule_id == "response-media-type-added"),
  )
  let range = @openapi.parse_specification(
    text.replace_all(old="application/json", new="application/*"),
    format=@openapi.Json,
  )
  assert_eq(@compat.compare(baseline, range).exit_code(), 2)
  let empty = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"post\":{}}}}",
    format=@openapi.Json,
  )
  let required = body_spec({ "type": "string" }, required=true)
  let added = @compat.compare(empty, required)
  assert_eq(added.exit_code(), 1)
  assert_eq(added.findings[0].rule_id, "request-body-added-required")
}
