///|
test "body, response and nested schema references use the bounded source graph" {
  let entry =
    #|{"openapi":"3.1.1","paths":{"/orders":{"post":{"requestBody":{"$ref":"payload.yaml#/body"},"responses":{"200":{"$ref":"payload.yaml#/response"}}}}}}
  let document = @openapi.parse_specification(
    entry,
    format=@openapi.Json,
    source="file:///entry.json",
    load=Some((_, path) => {
      if path != "payload.yaml" {
        raise @openapi.DocumentError("unexpected file")
      }
      {
        source: "file:///payload.yaml",
        format: @openapi.Yaml,
        text: "body:\n  content:\n    application/json:\n      schema: {$ref: '#/schema'}\nresponse:\n  description: ok\n  content:\n    application/json:\n      schema: {$ref: '#/schema'}\nschema:\n  type: array\n  items: {type: string}\n",
      }
    }),
  )
  assert_true(document.diagnostics.is_empty())
  let operation = document.operations[0]
  assert_eq(operation.request_body.unwrap().location.pointer, "/body")
  assert_eq(operation.responses[0].location.pointer, "/response")
  assert_eq(
    operation.responses[0].content[0].schema.unwrap().location.uri,
    "file:///payload.yaml",
  )
  assert_eq(
    operation.responses[0].content[0].schema.unwrap().location.pointer,
    "/schema",
  )
}

///|
test "recursive schemas, reference siblings and invalid payload types are incomplete" {
  for
    schema in [
      "{\"$ref\":\"#/components/schemas/S\"}", "{\"$ref\":\"#/components/schemas/S\",\"type\":\"string\"}",
      "{\"$id\":\"https://example.test/base\",\"type\":\"string\"}",
    ] {
    let text = "{\"openapi\":\"3.1.1\",\"components\":{\"schemas\":{\"S\":{\"type\":\"object\",\"properties\":{\"next\":{\"$ref\":\"#/components/schemas/S\"}}}}},\"paths\":{\"/orders\":{\"post\":{\"requestBody\":{\"content\":{\"application/json\":{\"schema\":" +
      schema +
      "}}}}}}}"
    let document = @openapi.parse_specification(text, format=@openapi.Json)
    assert_false(document.diagnostics.is_empty())
    assert_false(document.operations[0].complete)
  }
}

///|
test "references inside example values do not cause source loading" {
  let text =
    #|{"openapi":"3.1.1","paths":{"/orders":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","example":{"$ref":"remote.json"}}}}}}}}}
  let document = @openapi.parse_specification(text, format=@openapi.Json)
  assert_true(document.diagnostics.is_empty())
}
