///|
test "request and response directions, nullable and enums preserve exact instances" {
  let wide = @schema.parse({ "type": "string", "enum": ["read", "write"] })
  let narrow = @schema.parse({ "type": "string", "enum": ["read"] })
  assert_true(@schema.subset(narrow, wide) is Included)
  match @schema.subset(wide, narrow) {
    Excluded(value) => {
      assert_true(wide.accepts(value))
      assert_false(narrow.accepts(value))
    }
    _ => fail("expected enum witness")
  }
  let nullable = @schema.parse(
    { "type": "string", "nullable": true },
    openapi_30=true,
  )
  let union = @schema.parse({ "type": ["null", "string"] })
  assert_true(@schema.subset(nullable, union) is Included)
  assert_true(@schema.subset(union, nullable) is Included)
  assert_true(
    @schema.parse({ "nullable": true }, openapi_30=true).accepts(Json::null()),
  )
  let integer = @schema.parse({ "type": "integer" })
  let number = @schema.parse({ "type": "number" })
  assert_true(@schema.subset(integer, number) is Included)
  assert_true(@schema.subset(number, integer) is Excluded(_))
}

///|
test "objects and arrays generate witnesses for nested constraints" {
  let old = @schema.parse({
    "type": "object",
    "properties": { "name": { "type": "string" } },
  })
  let next = @schema.parse({
    "type": "object",
    "properties": { "name": { "type": "string" } },
    "required": ["name"],
  })
  assert_true(@schema.subset(next, old) is Included)
  assert_true(@schema.subset(old, next) is Excluded(_))
  let closed = @schema.parse({ "type": "object", "additionalProperties": false })
  assert_true(@schema.subset(old, closed) is Excluded(_))
  let before = @schema.parse({
    "type": "array",
    "items": {
      "type": "object",
      "properties": { "state": { "enum": ["ok", "error"] } },
    },
  })
  let after = @schema.parse({
    "type": "array",
    "items": { "type": "object", "properties": { "state": { "enum": ["ok"] } } },
  })
  match @schema.subset(before, after) {
    Excluded(value) => {
      assert_true(before.accepts(value))
      assert_false(after.accepts(value))
    }
    _ => fail("expected nested array witness")
  }
}

///|
test "large numeric enums compare decimal values without a Double round trip" {
  let a = @schema.parse({
    "enum": [Json::number(9007199254740992, repr="9007199254740993")],
  })
  let b = @schema.parse({
    "enum": [Json::number(9007199254740992, repr="9007199254740992")],
  })
  assert_true(@schema.subset(a, b) is Excluded(_))
  let c = @schema.parse({ "enum": [Json::number(1, repr="1.00e+0")] })
  assert_true(@schema.subset(c, @schema.parse({ "enum": [1] })) is Included)
  assert_false(
    @schema.parse({ "type": "integer" }).accepts(Json::number(0, repr="1e-400")),
  )
}

///|
test "caller-owned enum data and returned witnesses cannot mutate a parsed Schema" {
  let fields = Map([("id", Json::number(1))])
  let original : Json = { "enum": [Json::object(fields)] }
  let schema = @schema.parse(original)
  fields["id"] = Json::number(2)
  assert_true(schema.accepts({ "id": 1 }))
  assert_false(schema.accepts({ "id": 2 }))
  match @schema.subset(schema, @schema.parse(Json::boolean(false))) {
    Excluded(Object(witness)) => witness["id"] = Json::number(3)
    _ => fail("expected object witness")
  }
  assert_true(schema.accepts({ "id": 1 }))
}

///|
test "unsupported assertions and malformed declarations return typed errors" {
  let invalid : Array[Json] = [
    { "allOf": [] },
    { "format": 1 },
    { "multipleOf": 1 },
    { "readOnly": "true" },
    { "type": ["string", "string"] },
    { "enum": [1, 1.0] },
    { "required": [1] },
    { "type": "unknown" },
    { "nullable": true },
  ]
  for value in invalid {
    let failed = try {
      ignore(@schema.parse(value))
      false
    } catch {
      @schema.SchemaError(_) => true
    }
    assert_true(failed)
  }
  assert_true(
    @schema.subset(@schema.parse(Json::boolean(false)), @schema.parse({}))
    is Included,
  )
}

///|
test "finite-domain oracle checks proofs and every generated witness" {
  // The domain is explicit; this evaluator does not call Schema.accepts.
  let domain : Array[Json] = [
    Json::null(),
    Json::boolean(false),
    Json::boolean(true),
    Json::string("a"),
    Json::string("b"),
    Json::number(0),
    Json::number(1),
  ]
  let schemas = []
  for mask in 1..<128 {
    let values = []
    for index, value in domain {
      if (mask & (1 << index)) != 0 {
        values.push(value)
      }
    }
    schemas.push(@schema.parse({ "enum": Json(values) }))
  }
  for left in 0..<127 {
    for right in 0..<127 {
      let expected = ((left + 1) & (right + 1)) == left + 1
      match @schema.subset(schemas[left], schemas[right]) {
        Included => assert_true(expected)
        Excluded(value) => {
          assert_false(expected)
          let mut index = -1
          for offset, item in domain {
            if item.stringify() == value.stringify() {
              index = offset
            }
          }
          assert_true(index >= 0)
          assert_true(((left + 1) & (1 << index)) != 0)
          assert_true(((right + 1) & (1 << index)) == 0)
        }
        Unknown(_) => fail("finite enum inclusion is decidable")
      }
    }
  }
}

///|
fn object_oracle(
  value : Json,
  required : Int32,
  closed : Bool,
  mode : Int32,
) -> Bool {
  let fields = match value {
    Object(fields) => fields
    _ => return false
  }
  if (required & 1) != 0 && !fields.contains("x") {
    return false
  }
  if (required & 2) != 0 && !fields.contains("y") {
    return false
  }
  for (key, value) in fields {
    match key {
      "x" =>
        match value {
          Number(number, ..) => {
            if number.to_int().to_double() != number {
              return false
            }
            if mode == 1 && number != 0 && number != 1 {
              return false
            }
            if mode == 2 && number != 0 {
              return false
            }
          }
          _ => return false
        }
      "y" => if !(value is True || value is False) { return false }
      _ => if closed { return false }
    }
  }
  true
}

///|
test "object inclusion is checked by an independent finite assignment evaluator" {
  let cases = []
  for required in 0..<4 {
    for closed in [false, true] {
      for mode in 0..<3 {
        let names = []
        if (required & 1) != 0 {
          names.push("x")
        }
        if (required & 2) != 0 {
          names.push("y")
        }
        let x : Json = match mode {
          1 => { "enum": [0, 1] }
          2 => { "enum": [0] }
          _ => { "type": "integer" }
        }
        let schema = @schema.parse({
          "type": "object",
          "properties": { "x": x, "y": { "type": "boolean" } },
          "required": Json(names),
          "additionalProperties": !closed,
        })
        cases.push((required, closed, mode, schema))
      }
    }
  }
  let domain = []
  let xs : Array[Json?] = [
    None,
    Some(Json::null()),
    Some(Json::number(0)),
    Some(Json::number(1)),
    Some(Json::number(2)),
    Some(Json::string("x")),
  ]
  let ys : Array[Json?] = [
    None,
    Some(Json::null()),
    Some(Json::boolean(false)),
    Some(Json::boolean(true)),
  ]
  for x in xs {
    for y in ys {
      for extra in [false, true] {
        let fields = Map([])
        if x is Some(value) {
          fields["x"] = value
        }
        if y is Some(value) {
          fields["y"] = value
        }
        if extra {
          fields["extra"] = Json::number(0)
        }
        domain.push(Json::object(fields))
      }
    }
  }
  for (ar, ac, am, a) in cases {
    for (br, bc, bm, b) in cases {
      match @schema.subset(a, b) {
        Included =>
          for value in domain {
            assert_false(
              object_oracle(value, ar, ac, am) &&
              !object_oracle(value, br, bc, bm),
            )
          }
        Excluded(value) => {
          assert_true(object_oracle(value, ar, ac, am))
          assert_false(object_oracle(value, br, bc, bm))
        }
        Unknown(_) => ()
      }
    }
  }
}
