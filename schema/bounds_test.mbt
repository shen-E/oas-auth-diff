///|
test "bounds produce verified request and response counterexamples" {
  let cases : Array[(Json, Json)] = [
    ({ "type": "number", "minimum": -2 }, { "type": "number", "minimum": 2 }),
    ({ "type": "number", "maximum": 9 }, { "type": "number", "maximum": 3 }),
    (
      { "type": "integer", "minimum": 3 },
      { "type": "integer", "exclusiveMinimum": 3 },
    ),
    ({ "type": "string", "minLength": 1 }, { "type": "string", "minLength": 5 }),
    ({ "type": "string", "maxLength": 8 }, { "type": "string", "maxLength": 3 }),
    (
      { "type": "array", "items": { "type": "integer" }, "minItems": 2 },
      { "type": "array", "items": { "type": "integer" }, "minItems": 4 },
    ),
    (
      { "type": "object", "maxProperties": 4 },
      { "type": "object", "maxProperties": 2 },
    ),
    (
      { "type": "object", "minProperties": 1 },
      { "type": "object", "minProperties": 3 },
    ),
  ]
  for (wide, narrow) in cases {
    let a = @schema.parse(wide)
    let b = @schema.parse(narrow)
    assert_true(@schema.subset(b, a) is Included)
    match @schema.subset(a, b) {
      Excluded(value) => {
        assert_true(a.accepts(value))
        assert_false(b.accepts(value))
      }
      _ => fail("expected a bounded witness")
    }
  }
}

///|
test "integer rounding, legacy exclusivity and Unicode scalar lengths" {
  let cases : Array[(Json, Json)] = [
    ({ "minimum": 0.2 }, { "minimum": 1 }),
    ({ "maximum": -0.2 }, { "maximum": -1 }),
    ({ "exclusiveMinimum": -1 }, { "minimum": 0 }),
    ({ "exclusiveMaximum": 1 }, { "maximum": 0 }),
  ]
  for (a, b) in cases {
    let a = @schema.parse({ "allOf": [{ "type": "integer" }, a] })
    let b = @schema.parse({ "allOf": [{ "type": "integer" }, b] })
    assert_true(@schema.subset(a, b) is Included)
    assert_true(@schema.subset(b, a) is Included)
  }
  let old = @schema.parse(
    { "type": "number", "minimum": 3, "exclusiveMinimum": true },
    openapi_30=true,
  )
  let next = @schema.parse({ "type": "number", "exclusiveMinimum": 3 })
  assert_true(@schema.subset(old, next) is Included)
  assert_true(@schema.subset(next, old) is Included)
  let text = @schema.parse({ "type": "string", "minLength": 1, "maxLength": 1 })
  assert_true(text.accepts(Json::string("🚀")))
  assert_false(text.accepts(Json::string("é")))
  assert_true(
    @schema.parse({ "minimum": 10, "minLength": 3 }).accepts(
      Json::boolean(true),
    ),
  )
}

///|
test "bounds preserve decimal precision and avoid exponent-sized allocation" {
  let a = @schema.parse(
    @json.parse("{\"type\":\"integer\",\"minimum\":9007199254740992}"),
  )
  let b = @schema.parse(
    @json.parse("{\"type\":\"integer\",\"minimum\":9007199254740993}"),
  )
  assert_true(@schema.subset(a, b) is Excluded(_))
  assert_true(@schema.subset(b, a) is Included)
  let tiny = @schema.parse(
    @json.parse(
      "{\"type\":\"number\",\"minimum\":1e-1000000000}",
      preserve_number_repr=true,
    ),
  )
  assert_false(tiny.accepts(Json::number(0)))
  assert_true(
    tiny.accepts(@json.parse("2e-1000000000", preserve_number_repr=true)),
  )
  assert_true(
    @schema.subset(@schema.parse({ "type": "number", "minimum": 0 }), tiny)
    is Excluded(_),
  )
  let huge = @schema.parse({ "type": "string", "minLength": 1000000000 })
  assert_false(huge.accepts(Json::string("")))
  assert_true(
    @schema.subset(
      @schema.parse({ "type": "string", "minLength": 999999999 }),
      huge,
    )
    is Unknown(_),
  )
}

///|
test "bound assertions intersect with compositions and nested instance constraints" {
  let a = @schema.parse({
    "allOf": [{ "type": "number", "minimum": 1 }, { "maximum": 3 }],
  })
  let b = @schema.parse({ "type": "number", "minimum": 1, "maximum": 3 })
  assert_true(@schema.subset(a, b) is Included)
  assert_true(@schema.subset(b, a) is Included)
  let before = @schema.parse({
    "type": "array",
    "minItems": 3,
    "items": { "type": "string", "minLength": 2 },
  })
  let after = @schema.parse({
    "type": "array",
    "minItems": 3,
    "items": { "type": "string", "minLength": 5 },
  })
  assert_true(@schema.subset(before, after) is Excluded(_))
  let invalid_cases : Array[Json] = [
    { "minLength": -1 },
    { "maxItems": 1.5 },
    { "exclusiveMinimum": true },
  ]
  for invalid in invalid_cases {
    assert_true(
      try {
        ignore(@schema.parse(invalid))
        false
      } catch {
        _ => true
      },
    )
  }
}

///|
test "small integer interval inclusions agree with an independent enumerator" {
  for lower in -2..<3 {
    for upper in lower..<3 {
      for next_lower in -2..<3 {
        for next_upper in next_lower..<3 {
          let source = @schema.parse({
            "type": "integer",
            "minimum": lower,
            "maximum": upper,
          })
          let target = @schema.parse({
            "type": "integer",
            "minimum": next_lower,
            "maximum": next_upper,
          })
          let expected = lower >= next_lower && upper <= next_upper
          match @schema.subset(source, target) {
            Included => assert_true(expected)
            Excluded(value) => {
              assert_false(expected)
              assert_true(source.accepts(value))
              assert_false(target.accepts(value))
            }
            Unknown(message) => fail(message)
          }
        }
      }
    }
  }
}

///|
test "numeric bounds reject representations that overflow the input number policy" {
  let failed = try {
    ignore(@schema.parse({ "minimum": Json::number(0, repr="1e9999") }))
    false
  } catch {
    @schema.SchemaError(_) => true
  }
  assert_true(failed)
}
