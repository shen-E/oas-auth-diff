///|
test "readOnly and writeOnly change requiredness in the selected direction" {
  for legacy in [false, true] {
    let value : Json = {
      "type": "object",
      "required": ["id", "secret", "name"],
      "properties": {
        "id": { "type": "integer", "readOnly": true },
        "secret": { "type": "string", "writeOnly": true },
        "name": { "type": "string" },
      },
    }
    let request = @schema.parse(
      value,
      openapi_30=legacy,
      direction=@schema.Request,
    )
    let response = @schema.parse(
      value,
      openapi_30=legacy,
      direction=@schema.Response,
    )
    let neutral = @schema.parse(value, openapi_30=legacy)
    assert_true(request.accepts({ "secret": "token", "name": "user" }))
    assert_false(response.accepts({ "secret": "token", "name": "user" }))
    assert_true(response.accepts({ "id": 1, "name": "user" }))
    assert_false(neutral.accepts({ "id": 1, "name": "user" }))
    // Projection relaxes requiredness; it does not drop constraints on supplied values.
    assert_false(
      request.accepts({ "id": "bad", "secret": "token", "name": "user" }),
    )
  }
}

///|
test "directional requiredness crosses allOf without modifying caller data" {
  let value : Json = {
    "allOf": [
      {
        "type": "object",
        "properties": {
          "id": { "allOf": [{ "type": "integer" }, { "readOnly": true }] },
        },
      },
      { "required": ["id"] },
    ],
  }
  let request = @schema.parse(value, direction=@schema.Request)
  let response = @schema.parse(value, direction=@schema.Response)
  assert_true(request.accepts({}))
  assert_false(response.accepts({}))
  assert_true(@schema.subset(response, request) is Included)
  assert_true(@schema.subset(request, response) is Excluded(_))
  assert_true(value.stringify().contains("readOnly"))
  let array = @schema.parse(
    { "type": "array", "items": value },
    direction=@schema.Request,
  )
  assert_true(array.accepts([{}]))
}

///|
test "conditional visibility stays explicit and annotations are typed" {
  let conditional : Json = {
    "anyOf": [
      { "properties": { "id": { "readOnly": true } } },
      { "required": ["id"] },
    ],
  }
  let refused = try {
    ignore(@schema.parse(conditional, direction=@schema.Request))
    false
  } catch {
    @schema.SchemaError(_) => true
  }
  assert_true(refused)
  ignore(@schema.parse(conditional))
  for
    value in (
      [{ "readOnly": "yes" }, { "writeOnly": 1 }, { "format": 1 }] : Array[Json]) {
    assert_true(
      try {
        ignore(@schema.parse(value))
        false
      } catch {
        @schema.SchemaError(_) => true
      },
    )
  }
  assert_true(
    try {
      ignore(
        @schema.parse({ "readOnly": true, "writeOnly": true }, openapi_30=true),
      )
      false
    } catch {
      @schema.SchemaError(_) => true
    },
  )
  assert_true(
    @schema.parse({ "type": "string", "format": "email" }).accepts(
      Json::string("annotation"),
    ),
  )
}

///|
test "projection does not erase malformed required declarations" {
  let value : Json = {
    "type": "object",
    "properties": { "id": { "readOnly": true } },
    "required": ["id", "id"],
  }
  assert_true(
    try {
      ignore(@schema.parse(value, direction=@schema.Request))
      false
    } catch {
      @schema.SchemaError(_) => true
    },
  )
}
