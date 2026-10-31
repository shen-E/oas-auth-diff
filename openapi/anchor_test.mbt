///|
fn anchor_resolver(value : Json) -> @openapi.ReferenceResolver raise {
  @openapi.ReferenceResolver::new({
    source: "file:///api.json",
    text: value.stringify(),
    format: @openapi.Json,
  })
}

///|
test "static Schema anchors support forward names and percent decoding without changing pointer resolution" {
  let resolver = anchor_resolver({
    "openapi": "3.1.1",
    "paths": {},
    "components": {
      "schemas": {
        "Use": { "$ref": "#Identifier" },
        "Id": { "$anchor": "Identifier", "type": "string" },
      },
    },
    "x-data": { "$anchor": "Identifier", "type": 0 },
  })
  let at : @openapi.Location = {
    uri: "file:///api.json",
    pointer: "/components/schemas/Use/$ref",
  }
  for reference in ["#Identifier", "#%49dentifier", "#/components/schemas/Id"] {
    match resolver.resolve_schema(reference, at) {
      Ok((value, location)) => {
        assert_eq(location.pointer, "/components/schemas/Id")
        assert_eq(
          value.stringify(),
          "{\"$anchor\":\"Identifier\",\"type\":\"string\"}",
        )
      }
      Err(d) => fail(d.message)
    }
  }
  assert_true(resolver.resolve("#Identifier", at) is Err(_))
  assert_true(resolver.resolve_schema("#absent", at) is Err(_))
}

///|
test "standalone Schema anchors keep external source origins and load once" {
  let calls = []
  let resolver = @openapi.ReferenceResolver::new(
    { source: "file:///api.json", text: "{}", format: @openapi.Json, },
    load=Some((from, path) => {
      calls.push((from, path))
      {
        source: "file:///model.json",
        text: "{\"$defs\":{\"Id\":{\"$anchor\":\"Id\",\"type\":\"integer\"}}}",
        format: @openapi.Json,
      }
    }),
  )
  let at : @openapi.Location = { uri: "file:///api.json", pointer: "", }
  for _ in 0..<2 {
    match resolver.resolve_schema("model.json#Id", at) {
      Ok((_, location)) => {
        assert_eq(location.uri, "file:///model.json")
        assert_eq(location.pointer, "/$defs/Id")
      }
      Err(d) => fail(d.message)
    }
  }
  assert_eq(calls, [("file:///api.json", "model.json")])
}

///|
test "duplicate static and dynamic anchor names are ambiguous while data anchors are ignored" {
  for declaration in ["$anchor", "$dynamicAnchor"] {
    let other = Json::object(Map([(declaration, Json::string("Id"))]))
    let resolver = anchor_resolver({
      "$defs": { "A": { "$anchor": "Id" }, "B": other },
      "enum": [{ "$anchor": "Data" }],
      "default": { "$anchor": "Default" },
    })
    let at : @openapi.Location = { uri: "file:///api.json", pointer: "", }
    match resolver.resolve_schema("#Id", at) {
      Err(d) => assert_eq(d.code, "ref.anchor-ambiguous")
      _ => fail("duplicate anchor must not select a target")
    }
    for name in ["#Data", "#Default"] {
      match resolver.resolve_schema(name, at) {
        Err(d) => assert_eq(d.code, "ref.anchor-missing")
        _ => fail("data must not define a Schema anchor")
      }
    }
  }
}

///|
test "anchors do not cross resource IDs and pointer targets cannot bypass ancestor scopes" {
  let resolver = anchor_resolver({
    "$defs": {
      "Outer": { "$anchor": "Id", "type": "string" },
      "Scoped": {
        "$id": "https://example.test/model",
        "$defs": { "Inner": { "$anchor": "Id", "type": "integer" } },
      },
    },
  })
  let at : @openapi.Location = { uri: "file:///api.json", pointer: "", }
  match resolver.resolve_schema("#Id", at) {
    Ok((_, target)) => assert_eq(target.pointer, "/$defs/Outer")
    Err(d) => fail(d.message)
  }
  for
    (reference, origin) in [
      ("#/$defs/Scoped/$defs/Inner", at),
      ("#Id", { uri: at.uri, pointer: "/$defs/Scoped/$defs/Inner/$ref", }),
    ] {
    match resolver.resolve_schema(reference, origin) {
      Err(d) => assert_eq(d.code, "ref.schema-id")
      _ => fail("resource scope must stay incomplete")
    }
  }
}
