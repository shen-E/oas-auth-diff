///|
test "allOf intersects fields and preserves closed-object branch constraints" {
  let composed = @schema.parse({
    "allOf": [
      {
        "type": "object",
        "properties": { "id": { "type": "integer" } },
        "required": ["id"],
      },
      {
        "properties": { "state": { "enum": ["draft", "done"] } },
        "required": ["state"],
      },
    ],
  })
  let flat = @schema.parse({
    "type": "object",
    "required": ["state", "id"],
    "properties": {
      "id": { "type": "integer" },
      "state": { "enum": ["done", "draft"] },
    },
  })
  assert_true(@schema.subset(composed, flat) is Included)
  assert_true(@schema.subset(flat, composed) is Included)
  assert_true(composed.accepts({ "id": 1, "state": "done" }))
  assert_false(composed.accepts({ "id": 1 }))
  let closed = @schema.parse({
    "allOf": [
      { "type": "object", "additionalProperties": false },
      { "properties": { "id": { "type": "integer" } }, "required": ["id"] },
    ],
  })
  assert_false(closed.accepts({ "id": 1 }))
  assert_false(closed.accepts({}))
}

///|
test "oneOf counts overlapping branches and accepts only exactly one" {
  let any = @schema.parse({
    "anyOf": [{ "type": "number" }, { "type": "integer" }],
  })
  let one = @schema.parse({
    "oneOf": [{ "type": "number" }, { "type": "integer" }],
  })
  assert_true(any.accepts(Json::number(1)))
  assert_false(one.accepts(Json::number(1)))
  assert_true(one.accepts(Json::number(0.5)))
  match @schema.subset(any, one) {
    Excluded(value) => {
      assert_true(any.accepts(value))
      assert_false(one.accepts(value))
    }
    _ => fail("overlap must produce a validated witness")
  }
  let reordered = @schema.parse({
    "oneOf": [{ "type": "integer" }, { "type": "number" }],
  })
  assert_true(@schema.subset(one, reordered) is Included)
}

///|
test "disjoint tagged unions and type unions can prove compatibility" {
  let cat : Json = {
    "type": "object",
    "required": ["kind"],
    "properties": { "kind": { "const": "cat" } },
  }
  let dog : Json = {
    "type": "object",
    "required": ["kind"],
    "properties": { "kind": { "const": "dog" } },
  }
  let union = @schema.parse({ "oneOf": [cat, dog] })
  let either = @schema.parse({ "anyOf": [cat, dog] })
  assert_true(@schema.subset(either, union) is Included)
  assert_true(@schema.subset(@schema.parse(cat), union) is Included)
  assert_true(@schema.subset(union, @schema.parse(cat)) is Excluded(_))
  assert_true(
    @schema.subset(
      @schema.parse({ "type": ["string", "integer"] }),
      @schema.parse({ "oneOf": [{ "type": "integer" }, { "type": "string" }] }),
    )
    is Included,
  )
}

///|
test "finite composition truth tables independently check inclusion and witnesses" {
  let domain : Array[Json] = [
    Json::null(),
    Json::number(0),
    Json::string("a"),
    Json::string("b"),
  ]
  let cases = []
  for left in [3, 5, 10, 12] {
    for right in [3, 5, 10, 12] {
      let a = []
      let b = []
      for index, value in domain {
        if (left & (1 << index)) != 0 {
          a.push(value)
        }
        if (right & (1 << index)) != 0 {
          b.push(value)
        }
      }
      for keyword in ["allOf", "anyOf", "oneOf"] {
        let fields = Map([
          (keyword, Json::array([{ "enum": Json(a) }, { "enum": Json(b) }])),
        ])
        let expected = match keyword {
          "allOf" => left & right
          "anyOf" => left | right
          _ => left ^ right
        }
        cases.push((expected, @schema.parse(Json::object(fields))))
      }
    }
  }
  for (mask, schema) in cases {
    for index, value in domain {
      assert_eq(schema.accepts(value), (mask & (1 << index)) != 0)
    }
    for (target_mask, target) in cases {
      let expected = (mask & target_mask) == mask
      match @schema.subset(schema, target) {
        Included => assert_true(expected)
        Excluded(value) => {
          assert_false(expected)
          let mut offset = -1
          for index, candidate in domain {
            if candidate.stringify() == value.stringify() {
              offset = index
            }
          }
          assert_true(offset >= 0)
          assert_true((mask & (1 << offset)) != 0)
          assert_true((target_mask & (1 << offset)) == 0)
        }
        Unknown(_) => fail("finite supported composition must be decidable")
      }
    }
  }
}
