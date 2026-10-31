///|
test "string patterns report request and response witnesses in opposite directions" {
  let wide : Json = { "type": "string", "pattern": "^[a-z]+$" }
  let narrow : Json = { "type": "string", "pattern": "^[a-f]+$" }
  for legacy in ["3.0.3", "3.1.1"] {
    let request = @compat.compare(
      body_spec(wide, version=legacy),
      body_spec(narrow, version=legacy),
    )
    assert_eq(request.exit_code(), 1)
    assert_true(request.findings[0].witness is Some(String(_)))
    assert_eq(
      @compat.compare(
        body_spec(narrow, version=legacy),
        body_spec(wide, version=legacy),
      ).exit_code(),
      0,
    )
    assert_eq(
      @compat.compare(
        body_spec(narrow, response=true, version=legacy),
        body_spec(wide, response=true, version=legacy),
      ).exit_code(),
      1,
    )
  }
}

///|
test "format collection has an independent traversal limit" {
  let properties = Map([])
  for index in 0..<10000 {
    properties["p" + index.to_string()] = ({ "format": "uuid" } : Json)
  }
  let specification = body_spec({
    "type": "object",
    "properties": Json::object(properties),
  })
  let comparison = @compat.compare(specification, specification)
  assert_eq(comparison.exit_code(), 2)
  assert_true(comparison.diagnostics.any(d => d.code == "resource.formats"))
}

///|
test "directional annotation changes produce requiredness witnesses" {
  let ordinary : Json = {
    "type": "object",
    "properties": { "id": { "type": "integer" } },
    "required": ["id"],
  }
  let read : Json = {
    "type": "object",
    "properties": { "id": { "type": "integer", "readOnly": true } },
    "required": ["id"],
  }
  let write : Json = {
    "type": "object",
    "properties": { "id": { "type": "integer", "writeOnly": true } },
    "required": ["id"],
  }
  for version in ["3.0.3", "3.1.1"] {
    let request = @compat.compare(
      body_spec(read, version~),
      body_spec(ordinary, version~),
    )
    assert_eq(request.exit_code(), 1)
    assert_eq(request.findings[0].witness, Some(Json::object(Map([]))))
    assert_eq(
      @compat.compare(body_spec(ordinary, version~), body_spec(read, version~)).exit_code(),
      0,
    )
    let response = @compat.compare(
      body_spec(ordinary, response=true, version~),
      body_spec(write, response=true, version~),
    )
    assert_eq(response.exit_code(), 1)
    assert_eq(response.findings[0].witness, Some(Json::object(Map([]))))
    assert_eq(
      @compat.compare(
        body_spec(write, response=true, version~),
        body_spec(ordinary, response=true, version~),
      ).exit_code(),
      0,
    )
  }
}

///|
test "format annotations stay nonassertive while changed annotations retain findings and exit two" {
  let old : Json = { "type": "string", "format": "uuid", "pattern": "^[a-z]+$" }
  assert_eq(@compat.compare(body_spec(old), body_spec(old)).exit_code(), 0)
  let next : Json = {
    "type": "string",
    "format": "email",
    "pattern": "^[a-f]+$",
  }
  let comparison = @compat.compare(body_spec(old), body_spec(next))
  assert_eq(comparison.exit_code(), 2)
  assert_eq(comparison.findings.length(), 1)
  assert_true(
    comparison.diagnostics.any(d => {
      d.code == "compat.format" &&
      d.message.contains("uuid") &&
      d.message.contains("email")
    }),
  )
  let example : Json = { "type": "object", "example": { "format": "old" } }
  let changed : Json = { "type": "object", "example": { "format": "new" } }
  assert_eq(
    @compat.compare(body_spec(example), body_spec(changed)).exit_code(),
    0,
  )
}

///|
test "unchanged formats survive allOf reordering and reference description siblings" {
  let a : Json = { "allOf": [{ "format": "uuid" }, { "type": "string" }] }
  let b : Json = { "allOf": [{ "type": "string" }, { "format": "uuid" }] }
  assert_eq(@compat.compare(body_spec(a), body_spec(b)).exit_code(), 0)
  let text = "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"post\":{\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"$ref\":\"#/components/schemas/Id\"}}}}}}},\"components\":{\"schemas\":{\"Id\":{\"type\":\"string\",\"format\":\"uuid\"}}}}"
  let updated = text.replace_all(
    old="\"$ref\":\"#/components/schemas/Id\"",
    new="\"$ref\":\"#/components/schemas/Id\",\"description\":\"label\"",
  )
  assert_eq(
    @compat.compare(
      @openapi.parse_specification(text, format=@openapi.Json),
      @openapi.parse_specification(updated, format=@openapi.Json),
    ).exit_code(),
    0,
  )
}
