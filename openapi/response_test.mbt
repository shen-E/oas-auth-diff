///|
test "response header references retain their actual source and detect duplicates" {
  let text =
    #|{"openapi":"3.1.1","components":{"headers":{"Id":{"required":true,"schema":{"type":"string"}}}},"paths":{"/orders":{"get":{"responses":{"200":{"description":"ok","headers":{"X-ID":{"$ref":"#/components/headers/Id"}}}}}}}}
  let document = @openapi.parse_specification(text, format=@openapi.Json)
  assert_true(document.diagnostics.is_empty())
  let header = document.operations[0].responses[0].headers[0]
  assert_true(header.required)
  assert_eq(header.location.pointer, "/components/headers/Id")
  let duplicate = text.replace_all(
    old="\"X-ID\":{\"$ref\":\"#/components/headers/Id\"}",
    new="\"X-ID\":{},\"x-id\":{}",
  )
  let refused = @openapi.parse_specification(duplicate, format=@openapi.Json)
  assert_true(
    refused.diagnostics.any(d => d.code == "contract.header-duplicate"),
  )
}

///|
test "3.1 Schema reference siblings retain conjunctive constraints and ignore unused definitions" {
  let text =
    #|{"openapi":"3.1.1","paths":{"/orders":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$defs":{"State":{"type":"string","enum":["draft","done"]},"Unused":{"$ref":"https://example.test/unneeded.json"}},"$ref":"#/paths/~1orders/post/requestBody/content/application~1json/schema/$defs/State","enum":["done"]}}}}}}}}
  let document = @openapi.parse_specification(text, format=@openapi.Json)
  assert_true(document.diagnostics.is_empty())
  let schema = document.operations[0].request_body.unwrap().content[0].schema.unwrap()
  assert_true(schema.definition.stringify().contains("allOf"))
  assert_eq(
    schema.location.pointer,
    "/paths/~1orders/post/requestBody/content/application~1json/schema",
  )
}
