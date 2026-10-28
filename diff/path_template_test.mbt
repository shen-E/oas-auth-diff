///|
fn template_spec(paths : Json) -> String {
  let root : Json = {
    "openapi": "3.1.1",
    "components": {
      "securitySchemes": {
        "Key": { "type": "http", "scheme": "bearer" },
        "OAuth": {
          "type": "oauth2",
          "flows": {
            "clientCredentials": {
              "tokenUrl": "https://identity.example/token",
              "scopes": { "read": "Read", "write": "Write" },
            },
          },
        },
      },
    },
    "paths": paths,
  }
  root.stringify()
}

///|
fn template_document(
  path : String,
  security : Json,
) -> @openapi.Document raise @openapi.DocumentError {
  let item : Json = { "get": { "security": security } }
  @openapi.parse_document(
    template_spec(Json::object(Map([(path, item)]))),
    format=@openapi.Json,
    source="file:///routes.json",
  )
}

///|
fn template_operation(
  original : @openapi.Operation,
  path : String,
  verb~ : String = "GET",
) -> @openapi.Operation {
  let pointer = "/paths/" +
    path.replace_all(old="~", new="~0").replace_all(old="/", new="~1") +
    "/" +
    verb.to_lower()
  {
    ..original,
    http_method: verb,
    path,
    location: { uri: "file:///routes.json", pointer, },
    security_location: {
      uri: "file:///routes.json",
      pointer: pointer + "/security",
    },
  }
}

///|
fn template_change(
  result : @diff.Comparison,
  verb : String,
  path : String,
) -> @diff.OperationChange {
  result.changes
  .iter()
  .find_first(change => change.http_method == verb && change.path == path)
  .unwrap()
}

///|
test "parameter renaming retains anonymous regression and reverse strengthening" {
  let secured = template_document("/orders/{id}", [{ "Key": ["admin"] }])
  let anonymous = template_document("/orders/{order_id}", [])
  let result = @diff.compare(secured, anonymous)
  assert_true(result.complete)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.changes.length(), 1)
  let change = result.changes[0]
  assert_eq(change.kind, @diff.Weakened)
  assert_eq(change.path, "/orders/{order_id}")
  assert_eq(change.before_path, Some("/orders/{id}"))
  assert_eq(change.after_path, Some("/orders/{order_id}"))
  let witness = change.witness.unwrap()
  assert_true(witness.atoms().is_empty())
  assert_true(change.after.unwrap().allows(witness))
  assert_false(change.before.unwrap().allows(witness))
  let reverse = @diff.compare(anonymous, secured)
  assert_eq(reverse.exit_code(), 0)
  assert_eq(reverse.changes[0].kind, @diff.Strengthened)
  assert_eq(reverse.changes[0].before_path, change.after_path)
  assert_eq(reverse.changes[0].after_path, change.before_path)
}

///|
test "renamed multiple parameters and embedded literals retain scope witnesses" {
  let before = template_document("/orgs/{org}/files/{stem}.{ext}", [
    { "OAuth": ["read", "write"] },
  ])
  let after = template_document("/orgs/{tenant}/files/{name}.{suffix}", [
    { "OAuth": ["read"] },
  ])
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.changes.length(), 1)
  let witness = result.changes[0].witness.unwrap()
  assert_true(witness.atoms().contains(@logic.Scope("OAuth", "read")))
  assert_false(witness.atoms().contains(@logic.Scope("OAuth", "write")))
  assert_true(result.changes[0].after.unwrap().allows(witness))
  assert_false(result.changes[0].before.unwrap().allows(witness))
  let reordered = template_document("/orgs/{tenant}/files/{name}.{suffix}", [
    { "OAuth": ["write", "read"] },
  ])
  let equivalent = @diff.compare(before, reordered)
  assert_eq(equivalent.exit_code(), 0)
  assert_eq(equivalent.changes.length(), 1)
  assert_eq(equivalent.changes[0].kind, @diff.Equivalent)
}

///|
test "literal case slash and percent spellings never become parameter-only renames" {
  for
    (before_path, after_path) in [
      ("/pets/mine", "/pets/{name}"),
      ("/Orders/{id}", "/orders/{name}"),
      ("/pets/{id}/", "/pets/{name}"),
      ("/pets//{id}", "/pets/{name}"),
      ("/pets/%2f/{id}", "/pets/%2F/{name}"),
      ("/pets/%7Bid%7D", "/pets/{name}"),
      ("/files/{id}.json", "/files/{name}.yaml"),
    ] {
    let result = @diff.compare(
      template_document(before_path, [{ "Key": [] }]),
      template_document(after_path, []),
    )
    assert_eq(result.exit_code(), 0)
    assert_eq(result.changes.length(), 2)
    let removed = template_change(result, "GET", before_path)
    let added = template_change(result, "GET", after_path)
    assert_eq(removed.kind, @diff.Removed)
    assert_eq(removed.before_path, Some(before_path))
    assert_true(removed.after_path is None)
    assert_eq(added.kind, @diff.Added)
    assert_true(added.before_path is None)
    assert_eq(added.after_path, Some(after_path))
    assert_true(added.witness is None)
  }
}

///|
test "renamed reports expose both raw paths without changing candidate evidence" {
  let result = @diff.compare(
    template_document("/orders/{id}", [{ "Key": [] }]),
    template_document("/orders/{order_id}", []),
  )
  let description = "/orders/{id} -> /orders/{order_id}"
  assert_true(@diff.render_text(result).contains(description))
  let json = @json.parse(@diff.render_json(result), reject_duplicate_keys=true)
  match json {
    {
      "schema_version": Number(1, ..),
      "changes": Array(
        [
          {
            "path": String("/orders/{order_id}"),
            "before_path": String("/orders/{id}"),
            "after_path": String("/orders/{order_id}"),
            "location": {
              "pointer": String("/paths/~1orders~1{order_id}/get/security"),
              ..
            },
            ..
          },
        ]
      ),
      ..
    } => ()
    _ => fail("JSON lost raw paths or candidate evidence")
  }
  let sarif = @json.parse(
    @diff.render_sarif(result),
    reject_duplicate_keys=true,
  )
  match sarif {
    {
      "runs": Array(
        [
          {
            "tool": { "driver": { "version": String("0.7.0"), .. }, .. },
            "results": Array(
              [
                {
                  "message": { "text": String(message), .. },
                  "properties": {
                    "before_path": String("/orders/{id}"),
                    "after_path": String("/orders/{order_id}"),
                    ..
                  },
                  ..
                },
              ]
            ),
            ..
          },
        ]
      ),
      ..
    } => assert_true(message.contains(description))
    _ => fail("SARIF lost raw paths or release identity")
  }
}

///|
test "manual duplicate template paths across methods block the whole shape only" {
  let secured = template_document("/base", [{ "Key": [] }])
  let anonymous = template_document("/base", [])
  let strict = secured.operations[0]
  let public_access = anonymous.operations[0]
  let before : @openapi.Document = {
    ..secured,
    operations: [
      template_operation(strict, "/pets/{id}"),
      template_operation(strict, "/pets/{name}", verb="POST"),
      template_operation(strict, "/safe"),
    ],
  }
  let after : @openapi.Document = {
    ..anonymous,
    operations: [
      template_operation(public_access, "/pets/{item}"),
      template_operation(public_access, "/pets/{item}", verb="POST"),
      template_operation(public_access, "/safe"),
    ],
  }
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 2)
  assert_eq(result.changes.length(), 3)
  assert_eq(
    result.diagnostics.filter(d => d.code == "path-duplicate").length(),
    2,
  )
  for verb in ["GET", "POST"] {
    let change = template_change(result, verb, "/pets/{item}")
    assert_eq(change.kind, @diff.Incomparable)
    assert_true(change.before is None)
    assert_true(change.after is None)
    assert_true(change.witness is None)
  }
  let independent = template_change(result, "GET", "/safe")
  assert_eq(independent.kind, @diff.Weakened)
  assert_true(independent.witness is Some(_))
}

///|
test "manual exact duplicate method blocks no other method of the same raw path" {
  let secured = template_document("/base", [{ "Key": [] }])
  let anonymous = template_document("/base", [])
  let strict = secured.operations[0]
  let public_access = anonymous.operations[0]
  let before : @openapi.Document = {
    ..secured,
    operations: [
      template_operation(strict, "/pets/{id}"),
      template_operation(public_access, "/pets/{id}"),
      template_operation(strict, "/pets/{id}", verb="POST"),
    ],
  }
  let after : @openapi.Document = {
    ..anonymous,
    operations: [
      template_operation(public_access, "/pets/{name}"),
      template_operation(public_access, "/pets/{name}", verb="POST"),
    ],
  }
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 2)
  assert_eq(
    result.diagnostics.filter(d => d.code == "operation-duplicate").length(),
    1,
  )
  assert_false(result.diagnostics.any(d => d.code == "path-duplicate"))
  let duplicate = template_change(result, "GET", "/pets/{name}")
  assert_eq(duplicate.kind, @diff.Incomparable)
  assert_true(duplicate.witness is None)
  let separate_method = template_change(result, "POST", "/pets/{name}")
  assert_eq(separate_method.kind, @diff.Weakened)
  assert_true(separate_method.witness is Some(_))
}

///|
test "manual invalid templates cannot hide a valid same-spelling normalized shape" {
  let secured = template_document("/base", [{ "Key": [] }])
  let anonymous = template_document("/base", [])
  let strict = secured.operations[0]
  let public_access = anonymous.operations[0]
  let invalid_paths = [
    "/{}", "/pets/{", "/pets/}", "/pets/{{id}}", "/pets/{a/b}", "pets/{id}",
  ]
  let before_operations = invalid_paths.map(path => {
    template_operation(strict, path)
  })
  let after_operations = invalid_paths.map(path => {
    template_operation(public_access, path)
  })
  before_operations.push(template_operation(strict, "/{id}"))
  after_operations.push(template_operation(public_access, "/{name}"))
  let result = @diff.compare({ ..secured, operations: before_operations, }, {
    ..anonymous,
    operations: after_operations,
  })
  assert_eq(result.exit_code(), 2)
  assert_eq(result.changes.length(), invalid_paths.length() + 1)
  assert_eq(
    result.diagnostics.filter(d => d.code == "auth.path").length(),
    2 * invalid_paths.length(),
  )
  for path in invalid_paths {
    let change = template_change(result, "GET", path)
    assert_eq(change.kind, @diff.Incomparable)
    assert_true(change.before is None)
    assert_true(change.after is None)
    assert_true(change.witness is None)
  }
  let valid = template_change(result, "GET", "/{name}")
  assert_eq(valid.kind, @diff.Weakened)
  assert_true(valid.witness is Some(_))
}

///|
test "manual ambiguous operations produce stable reports regardless of input order" {
  let secured = template_document("/base", [{ "Key": [] }])
  let anonymous = template_document("/base", [])
  let before_operations = [
    template_operation(secured.operations[0], "/pets/{id}"),
    template_operation(anonymous.operations[0], "/pets/{name}"),
    template_operation(secured.operations[0], "/safe"),
  ]
  let after_operations = [
    template_operation(anonymous.operations[0], "/pets/{item}"),
    template_operation(anonymous.operations[0], "/safe"),
  ]
  let result = @diff.compare({ ..secured, operations: before_operations, }, {
    ..anonymous,
    operations: after_operations,
  })
  let reversed_before = [
    before_operations[2],
    before_operations[1],
    before_operations[0],
  ]
  let reversed_after = [after_operations[1], after_operations[0]]
  let reversed = @diff.compare({ ..secured, operations: reversed_before, }, {
    ..anonymous,
    operations: reversed_after,
  })
  assert_eq(result.exit_code(), 2)
  assert_eq(@diff.render_json(result), @diff.render_json(reversed))
  assert_eq(@diff.render_text(result), @diff.render_text(reversed))
  assert_eq(@diff.render_sarif(result), @diff.render_sarif(reversed))
}

///|
test "renamed paths participate in paired external scheme supplementation" {
  let before : @openapi.SourceDocument = {
    text: pair_spec({
      "/items/{id}": { "get": { "security": [{ "A": [], "B": [] }] } },
    }),
    format: @openapi.Json,
    source: "file:///before/openapi.json",
  }
  let after : @openapi.SourceDocument = {
    text: pair_spec({
      "/items/{item}": { "get": { "security": [{ "A": [] }] } },
    }),
    format: @openapi.Json,
    source: "file:///after/openapi.json",
  }
  let before_calls = []
  let after_calls = []
  let pair = @openapi.parse_pair(
    before,
    after,
    before_load=Some(
      pair_loader(
        { "file:///before/openapi.json|auth/b.json": pair_b_definition() },
        before_calls,
      ),
    ),
    after_load=Some(
      pair_loader(
        { "file:///after/openapi.json|auth/b.json": pair_b_definition() },
        after_calls,
      ),
    ),
  )
  assert_eq(before_calls.length(), 1)
  assert_eq(after_calls.length(), 1)
  let result = @diff.compare(pair.before, pair.after)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.changes.length(), 1)
  assert_eq(result.changes[0].before_path, Some("/items/{id}"))
  assert_eq(result.changes[0].after_path, Some("/items/{item}"))
  let witness = result.changes[0].witness.unwrap()
  assert_true(witness.atoms().contains(@logic.Credential("A")))
  assert_false(witness.atoms().contains(@logic.Credential("B")))
  assert_true(result.changes[0].after.unwrap().allows(witness))
  assert_false(result.changes[0].before.unwrap().allows(witness))
}
