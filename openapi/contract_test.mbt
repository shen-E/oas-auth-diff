///|
test "specification snapshots retain exact JSON and YAML numbers" {
  let json = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-values\":[9007199254740993,1.00000000000000001,1e-400]}",
    format=@openapi.Json,
  )
  let yaml = @openapi.parse_specification(
    "openapi: 3.1.1\npaths: {}\nx-values: [9007199254740993, 1.00000000000000001, 1e-400]\n",
    format=@openapi.Yaml,
  )
  assert_true(json.same_remainder(yaml))
  let text = json.to_json().stringify()
  assert_true(text.contains("9007199254740993"))
  assert_true(text.contains("1.00000000000000001"))
  let different = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-values\":[9007199254740992,1.00000000000000001,1e-400]}",
    format=@openapi.Json,
  )
  assert_false(json.same_remainder(different))
}

///|
test "YAML scalar spellings preserve exact numeric meaning" {
  let before = @openapi.parse_specification(
    "openapi: 3.1.1\npaths: {}\nx-numbers: [+001.00, .5, 1., 0x20000000000001, -0o10]\n",
    format=@openapi.Yaml,
  )
  let after = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-numbers\":[1e0,0.5,1,9007199254740993,-8]}",
    format=@openapi.Json,
  )
  assert_true(before.same_remainder(after))
  assert_true(before.to_json().stringify().contains("9007199254740993"))
}

///|
test "effective parameters inherit, override and retain reference origins" {
  let specification = @openapi.parse_specification(
    "{\"openapi\":\"3.0.3\",\"paths\":{\"/orders\":{\"parameters\":[{\"name\":\"tenant\",\"in\":\"query\",\"required\":true}],\"get\":{\"parameters\":[{\"$ref\":\"#/components/parameters/Tenant\"}],\"responses\":{}}}},\"components\":{\"parameters\":{\"Tenant\":{\"name\":\"tenant\",\"in\":\"query\",\"required\":false}}}}",
    format=@openapi.Json,
    source="file:///api.json",
  )
  assert_true(specification.diagnostics.is_empty())
  assert_eq(specification.operations.length(), 1)
  let parameter = specification.operations[0].parameters[0]
  assert_eq(parameter.name, "tenant")
  assert_false(parameter.required)
  assert_eq(parameter.location.pointer, "/components/parameters/Tenant")
}

///|
test "parameters use the bounded local source graph" {
  let mut reads = 0
  let document = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"get\":{\"parameters\":[{\"$ref\":\"parameter.yaml\"}]}}}}",
    format=@openapi.Json,
    source="file:///entry.json",
    load=Some((_, name) => {
      if name != "parameter.yaml" {
        raise @openapi.DocumentError("unexpected loader path")
      }
      reads += 1
      {
        text: "name: tenant\nin: query\nrequired: true\n",
        format: @openapi.Yaml,
        source: "file:///parameter.yaml",
      }
    }),
  )
  assert_true(document.diagnostics.is_empty())
  assert_eq(reads, 1)
  assert_eq(
    document.operations[0].parameters[0].location.uri,
    "file:///parameter.yaml",
  )
}

///|
test "malformed parameter declarations make the affected operation incomplete" {
  for
    parameters in [
      "{}", "[1]", "[{\"name\":\"q\",\"in\":\"body\"}]", "[{\"name\":\"q\",\"in\":\"query\",\"required\":1}]",
      "[{\"name\":\"q\",\"in\":\"query\"},{\"name\":\"q\",\"in\":\"query\"}]", "[{\"name\":\"X-ID\",\"in\":\"header\"},{\"name\":\"x-id\",\"in\":\"header\"}]",
      "[{\"$ref\":\"#/absent\"}]", "[{\"$ref\":\"https://example.test/p\"}]",
    ] {
    let document = @openapi.parse_specification(
      "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"get\":{\"parameters\":" +
      parameters +
      "}}}}",
      format=@openapi.Json,
    )
    assert_false(document.diagnostics.is_empty())
    assert_false(document.operations[0].complete)
  }
}

///|
test "path parameters are checked against the template" {
  for
    parameters in [
      "[]", "[{\"name\":\"id\",\"in\":\"path\"}]", "[{\"name\":\"other\",\"in\":\"path\",\"required\":true}]",
    ] {
    let document = @openapi.parse_specification(
      "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders/{id}\":{\"get\":{\"parameters\":" +
      parameters +
      "}}}}",
      format=@openapi.Json,
    )
    assert_false(document.diagnostics.is_empty())
  }
}

///|
test "snapshot calls do not expose the parser's retained maps" {
  let document = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-value\":1}",
    format=@openapi.Json,
  )
  match document.to_json() {
    Object(fields) => fields["x-value"] = Json::number(2)
    _ => fail("expected object")
  }
  assert_true(document.to_json().stringify().contains("\"x-value\":1"))
}

///|
test "unevaluated schema references never return a clean parameter analysis" {
  for
    extra in [
      "\"parameters\":[{\"name\":\"q\",\"in\":\"query\",\"schema\":{\"$ref\":\"schema.json\"}}]",
      "\"responses\":{\"200\":{\"content\":{\"application/json\":{\"schema\":{\"$ref\":\"#/components/schemas/X\"}}}}}",
    ] {
    let document = @openapi.parse_specification(
      "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"get\":{" +
      extra +
      "}}}}",
      format=@openapi.Json,
    )
    assert_true(
      document.diagnostics.any(d => d.code == "contract.unevaluated-ref"),
    )
    assert_false(document.operations[0].complete)
  }
}

///|
test "shared parameter expansion is bounded even when the source is cached" {
  let paths : Map[String, Json] = Map([])
  for index in 0..<220 {
    paths["/item/" + index.to_string()] = {
      "get": { "parameters": [{ "$ref": "parameter.json" }] },
    }
  }
  let entry : Json = { "openapi": "3.1.1", "paths": Json::object(paths) }
  let parameter : Json = {
    "name": "q",
    "in": "query",
    "schema": { "enum": Json(Array::make(5000, "x")) },
  }
  let document = @openapi.parse_specification(
    entry.stringify(),
    format=@openapi.Json,
    source="file:///entry.json",
    load=Some((_, _) => {
      text: parameter.stringify(),
      format: @openapi.Json,
      source: "file:///parameter.json",
    }),
  )
  assert_true(
    document.diagnostics.any(d => d.code == "resource.contract-nodes"),
  )
  assert_true(document.operations.length() < 220)
}
