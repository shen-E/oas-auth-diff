///|
fn loaded_document(
  text : String,
  sources : Map[String, @openapi.SourceDocument],
  calls : Array[String],
) -> @openapi.Document raise @openapi.DocumentError {
  @openapi.parse_with_loader(
    text,
    format=@openapi.Json,
    source="file:///spec/openapi.json",
    load=(from, relative) => {
      let key = from + "|" + relative
      calls.push(key)
      match sources.get(key) {
        Some(document) => document
        None => raise @openapi.DocumentError("No supplied document: " + key)
      }
    },
  )
}

///|
fn entry_with_paths(paths : Json, security~ : Json = []) -> String {
  let root : Json = {
    "openapi": "3.1.1",
    "components": {
      "securitySchemes": { "Key": { "type": "http", "scheme": "bearer" } },
    },
    "security": security,
    "paths": paths,
  }
  root.stringify()
}

///|
test "multi-file relative and local references preserve entry security and external evidence" {
  let entry = entry_with_paths({ "/data": { "$ref": "parts/b.yaml#/item" } }, security=[
    { "Key": ["admin"] },
  ])
  let middle : @openapi.SourceDocument = {
    source: "file:///spec/parts/b.yaml",
    format: @openapi.Yaml,
    text: (
      #|item:
      #|  $ref: '#/shared'
      #|shared:
      #|  $ref: 'defs/c.json#/item'
      #|components:
      #|  securitySchemes:
      #|    Key:
      #|      type: http
      #|      scheme: basic
    ),
  }
  let target =
    #|{"item":{"get":{"security":[{"Key":["admin"]}]},"post":{}},"security":[],"components":{"securitySchemes":{"Key":{"type":"apiKey","name":"Wrong-Key","in":"query"}}}}
  let old_calls = []
  let old_sources : Map[String, @openapi.SourceDocument] = {
    "file:///spec/openapi.json|parts/b.yaml": middle,
    "file:///spec/parts/b.yaml|defs/c.json": {
      source: "file:///spec/parts/defs/c.json",
      format: @openapi.Json,
      text: target,
    },
  }
  let before = loaded_document(entry, old_sources, old_calls)
  let new_sources = old_sources.copy()
  new_sources["file:///spec/parts/b.yaml|defs/c.json"] = {
    source: "file:///spec/parts/defs/c.json",
    format: @openapi.Json,
    text: target.replace_all(old="[\"admin\"]", new="[]"),
  }
  let new_calls = []
  let after = loaded_document(entry, new_sources, new_calls)
  assert_eq(old_calls.length(), 2)
  assert_eq(new_calls, old_calls)
  assert_eq(before.diagnostics.length(), 0)
  assert_eq(after.diagnostics.length(), 0)
  assert_eq(before.operations.length(), 2)
  let inherited = before.operations
    .iter()
    .find_first(operation => operation.http_method == "POST")
    .unwrap()
  assert_eq(inherited.security_location.uri, "file:///spec/openapi.json")
  assert_eq(inherited.security_location.pointer, "/security")
  assert_false(inherited.policy.unwrap().allows(@logic.GrantSet::new([])))
  assert_eq(before.schemes.length(), 1)
  assert_true(before.schemes[0].fingerprint.contains("bearer"))
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 1)
  let weakened = result.changes
    .iter()
    .find_first(change => change.http_method == "GET")
    .unwrap()
  assert_eq(weakened.kind, @diff.Weakened)
  let grants = weakened.witness.unwrap()
  assert_true(weakened.after.unwrap().allows(grants))
  assert_false(weakened.before.unwrap().allows(grants))
  assert_eq(weakened.location.uri, "file:///spec/parts/defs/c.json")
  assert_eq(weakened.location.pointer, "/item/get/security")
  let json = @json.parse(@diff.render_json(result))
  match json {
    { "changes": Array(changes), .. } =>
      assert_true(
        changes.any(fn(change) {
          match change {
            {
              "kind": String("weakened"),
              "location": {
                "uri": String("file:///spec/parts/defs/c.json"),
                "pointer": String("/item/get/security"),
                ..
              },
              ..
            } => true
            _ => false
          }
        }),
      )
    _ => fail("missing JSON operation changes")
  }
  let sarif = @json.parse(@diff.render_sarif(result))
  match sarif {
    {
      "runs": Array(
        [
          {
            "results": Array(
              [
                {
                  "locations": Array(
                    [
                      {
                        "physicalLocation": {
                          "artifactLocation": { "uri": String(uri), .. },
                          ..
                        },
                        "properties": { "jsonPointer": String(pointer), .. },
                        ..
                      },
                    ]
                  ),
                  ..
                },
              ]
            ),
            ..
          },
        ]
      ),
      ..
    } => {
      assert_eq(uri, "file:///spec/parts/defs/c.json")
      assert_eq(pointer, "/item/get/security")
    }
    _ => fail("SARIF lost external authentication evidence")
  }
}

///|
test "whole-file path and scheme references reuse a loaded document" {
  let entry =
    #|{"openapi":"3.1.1","components":{"securitySchemes":{"Key":{"$ref":"auth.json"}}},"paths":{"/first":{"$ref":"whole.yaml"},"/second":{"$ref":"whole.yaml#"}}}
  let sources : Map[String, @openapi.SourceDocument] = {
    "file:///spec/openapi.json|auth.json": {
      source: "file:///spec/auth.json",
      format: @openapi.Json,
      text: "{\"type\":\"apiKey\",\"name\":\"X-Key\",\"in\":\"header\"}",
    },
    "file:///spec/openapi.json|whole.yaml": {
      source: "file:///spec/whole.yaml",
      format: @openapi.Yaml,
      text: "get:\n  security:\n    - Key: []\n",
    },
  }
  let calls = []
  let document = loaded_document(entry, sources, calls)
  assert_eq(document.diagnostics.length(), 0)
  assert_eq(document.operations.length(), 2)
  assert_eq(calls.length(), 2)
  for operation in document.operations {
    assert_eq(operation.location.uri, "file:///spec/whole.yaml")
    assert_eq(operation.location.pointer, "/get")
    assert_false(operation.policy.unwrap().allows(@logic.GrantSet::new([])))
  }
  assert_eq(document.schemes[0].location.uri, "file:///spec/auth.json")
  assert_eq(document.schemes[0].location.pointer, "")
}

///|
test "percent-encoded file names reach the loader decoded once" {
  let calls = []
  let document = loaded_document(
    entry_with_paths({ "/data": { "$ref": "parts/path%20item.json#/item" } }),
    {
      "file:///spec/openapi.json|parts/path item.json": {
        source: "file:///spec/parts/path%20item.json",
        format: @openapi.Json,
        text: "{\"item\":{\"get\":{}}}",
      },
    },
    calls,
  )
  assert_eq(document.diagnostics.length(), 0)
  assert_eq(calls, ["file:///spec/openapi.json|parts/path item.json"])
  assert_eq(document.operations.length(), 1)
  assert_eq(
    document.operations[0].location.uri,
    "file:///spec/parts/path%20item.json",
  )
}

///|
test "cross-file cycles and missing or malformed files retain independent regressions" {
  let before_text = entry_with_paths({
    "/valid": { "get": { "security": [{ "Key": ["admin"] }] } },
    "/cycle": { "$ref": "b.json#/item" },
    "/missing": { "$ref": "missing.json#/item" },
    "/syntax": { "$ref": "invalid.yaml" },
  })
  let sources : Map[String, @openapi.SourceDocument] = {
    "file:///spec/openapi.json|b.json": {
      source: "file:///spec/b.json",
      format: @openapi.Json,
      text: "{\"item\":{\"$ref\":\"c.json#/item\"}}",
    },
    "file:///spec/b.json|c.json": {
      source: "file:///spec/c.json",
      format: @openapi.Json,
      text: "{\"item\":{\"$ref\":\"b.json#/item\"}}",
    },
    "file:///spec/c.json|b.json": {
      source: "file:///spec/b.json",
      format: @openapi.Json,
      text: "{\"item\":{\"$ref\":\"c.json#/item\"}}",
    },
    "file:///spec/openapi.json|invalid.yaml": {
      source: "file:///spec/invalid.yaml",
      format: @openapi.Yaml,
      text: "get: [\n",
    },
  }
  let before = loaded_document(before_text, sources, [])
  let after = loaded_document(
    before_text.replace_all(old="[\"admin\"]", new="[]"),
    sources,
    [],
  )
  assert_true(after.diagnostics.length() >= 3)
  assert_true(after.diagnostics.any(issue => issue.code == "ref.cycle"))
  assert_true(after.diagnostics.any(issue => issue.code == "ref.load"))
  assert_true(after.diagnostics.any(issue => issue.code == "ref.input"))
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 2)
  assert_false(result.complete)
  let valid = result.changes
    .iter()
    .find_first(change => change.path == "/valid")
    .unwrap()
  assert_eq(valid.kind, @diff.Weakened)
  let witness = valid.witness.unwrap()
  assert_true(valid.after.unwrap().allows(witness))
  assert_false(valid.before.unwrap().allows(witness))
}

///|
test "irrelevant external schemas never invoke the document loader" {
  let entry = entry_with_paths({
    "/data": {
      "get": {
        "security": [{ "Key": ["admin"] }],
        "responses": {
          "200": {
            "content": {
              "application/json": {
                "schema": { "$ref": "https://example.invalid/schema.json" },
              },
            },
          },
        },
      },
    },
  })
  let calls = []
  let before = loaded_document(entry, {}, calls)
  let after = loaded_document(
    entry.replace_all(old="[\"admin\"]", new="[]"),
    {},
    calls,
  )
  assert_true(calls.is_empty())
  assert_eq(@diff.compare(before, after).exit_code(), 1)
}

///|
test "unused external security definitions never invoke the document loader" {
  let entry =
    #|{"openapi":"3.1.1","components":{"securitySchemes":{"Key":{"type":"http","scheme":"bearer"},"Unused":{"$ref":"unused.yaml"}}},"paths":{"/data":{"get":{"security":[{"Key":["admin"]}]}}}}
  let calls = []
  let before = loaded_document(entry, {}, calls)
  let after = loaded_document(
    entry.replace_all(old="[\"admin\"]", new="[]"),
    {},
    calls,
  )
  assert_true(calls.is_empty())
  assert_eq(before.diagnostics.length(), 0)
  assert_eq(after.diagnostics.length(), 0)
  assert_eq(@diff.compare(before, after).exit_code(), 1)
}

///|
test "API-key header names ignore case while query and cookie names retain identity" {
  for where_ in ["header", "query", "cookie"] {
    let value : Json = {
      "openapi": "3.1.1",
      "components": {
        "securitySchemes": {
          "Key": { "type": "apiKey", "in": where_, "name": "X-Key" },
        },
      },
      "paths": { "/data": { "get": { "security": [{ "Key": [] }] } } },
    }
    let text = value.stringify()
    let before = @openapi.parse_document(text, format=@openapi.Json)
    let after = @openapi.parse_document(
      text.replace_all(old="X-Key", new="x-key"),
      format=@openapi.Json,
    )
    let result = @diff.compare(before, after)
    if where_ == "header" {
      assert_eq(result.exit_code(), 0)
      assert_eq(result.changes[0].kind, @diff.Equivalent)
    } else {
      assert_eq(result.exit_code(), 2)
      assert_eq(result.changes[0].kind, @diff.Incomparable)
    }
  }
}

///|
test "repeated path references cannot amplify extracted operations beyond the budget" {
  let paths : Map[String, Json] = Map([])
  for index in 0..<10001 {
    paths["/path-" + index.to_string()] = { "$ref": "item.json" }
  }
  let calls = []
  let document = loaded_document(
    entry_with_paths(Json::object(paths)),
    {
      "file:///spec/openapi.json|item.json": {
        source: "file:///spec/item.json",
        format: @openapi.Json,
        text: "{\"get\":{}}",
      },
    },
    calls,
  )
  assert_eq(calls.length(), 1)
  assert_true(
    document.operations
    .filter(operation => operation.policy is Some(_))
    .length() <=
    10000,
  )
  assert_true(
    document.diagnostics.any(issue => issue.code == "resource.operations"),
  )
  assert_eq(@diff.compare(document, document).exit_code(), 2)
}

///|
test "inherited and referenced security both charge expanded authentication atoms" {
  for inherited in [true, false] {
    let roles = Array::makei(64, index => Json("role-" + index.to_string()))
    let security : Json = [{ "Key": Json::array(roles) }]
    let item : Json = if inherited {
      { "get": {} }
    } else {
      { "get": { "security": security } }
    }
    let paths : Map[String, Json] = Map([])
    for index in 0..<4000 {
      paths["/path-" + index.to_string()] = { "$ref": "item.json" }
    }
    let calls = []
    let document = loaded_document(
      entry_with_paths(
        Json::object(paths),
        security=if inherited { security } else { [] },
      ),
      {
        "file:///spec/openapi.json|item.json": {
          source: "file:///spec/item.json",
          format: @openapi.Json,
          text: item.stringify(),
        },
      },
      calls,
    )
    assert_eq(calls.length(), 1)
    assert_true(
      document.diagnostics.any(issue => issue.code == "resource.atoms"),
    )
    assert_true(document.operations.any(operation => operation.policy is None))
    assert_eq(@diff.compare(document, document).exit_code(), 2)
  }
}
