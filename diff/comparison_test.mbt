///|
fn document(security : Json, extra~ : Json = {}) -> @openapi.Document raise {
  let spec : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Orders", "version": "1" },
    "components": {
      "securitySchemes": {
        "account": {
          "type": "oauth2",
          "flows": {
            "clientCredentials": {
              "tokenUrl": "https://identity.example/token",
              "scopes": { "read": "Read", "write": "Write" },
            },
          },
        },
        "key": { "type": "apiKey", "in": "header", "name": "X-Key" },
      },
    },
    "security": security,
    "paths": {
      "/orders": {
        "get": { "responses": { "200": { "description": "Orders" } } },
      },
      "/extra": extra,
    },
  }
  @openapi.parse_document(
    spec.stringify(),
    format=Json,
    source="file:///orders.json",
  )
}

///|
test "scope weakening contains independently evaluated witness" {
  let before = document([{ "account": ["read", "write"] }])
  let after = document([{ "account": ["read"] }])
  let comparison = @diff.compare(before, after)
  assert_true(comparison.complete)
  assert_eq(comparison.exit_code(), 1)
  assert_eq(comparison.changes.length(), 1)
  let change = comparison.changes[0]
  assert_eq(change.kind, @diff.Weakened)
  let witness = change.witness.unwrap()
  assert_true(change.after.unwrap().allows(witness))
  assert_false(change.before.unwrap().allows(witness))
  assert_true(witness.atoms().contains(@logic.Scope("account", "read")))
  assert_false(witness.atoms().contains(@logic.Scope("account", "write")))
}

///|
test "equivalent strengthened mixed and anonymous relations" {
  let strict = document([{ "account": ["read", "write"] }])
  let reordered = document([{ "account": ["write", "read", "read"] }])
  let read = document([{ "account": ["read"] }])
  let key = document([{ "key": [] }])
  let anonymous = document([])
  assert_eq(@diff.compare(strict, reordered).changes[0].kind, @diff.Equivalent)
  assert_eq(@diff.compare(read, strict).changes[0].kind, @diff.Strengthened)
  assert_eq(@diff.compare(read, strict).exit_code(), 0)
  let mixed = @diff.compare(read, key)
  assert_eq(mixed.changes[0].kind, @diff.Mixed)
  assert_eq(mixed.exit_code(), 1)
  assert_true(mixed.changes[0].witness is Some(_))
  let removed_requirement = @diff.compare(read, anonymous)
  assert_eq(removed_requirement.exit_code(), 1)
  assert_true(
    removed_requirement.changes[0].witness.unwrap().atoms().is_empty(),
  )
}

///|
test "AND to OR weakens and added anonymous operations are nonblocking" {
  let both = document([{ "account": ["read"], "key": [] }])
  let either = document([{ "account": ["read"] }, { "key": [] }])
  assert_eq(@diff.compare(both, either).changes[0].kind, @diff.Weakened)
  let addition = document([{ "account": ["read"] }], extra={
    "post": { "security": [], "responses": { "200": { "description": "ok" } } },
  })
  let comparison = @diff.compare(document([{ "account": ["read"] }]), addition)
  assert_eq(comparison.exit_code(), 0)
  assert_eq(comparison.changes[0].kind, @diff.Added)
  assert_true(
    @diff.render_text(comparison).contains("anonymous operation; review"),
  )
  assert_eq(
    @diff.compare(addition, document([{ "account": ["read"] }])).changes[0].kind,
    @diff.Removed,
  )
}

///|
test "incomplete analysis retains a regression on another operation" {
  let before = document([{ "account": ["read", "write"] }])
  let after_base = document([{ "account": ["read"] }])
  let after : @openapi.Document = {
    source: after_base.source,
    document_url: after_base.document_url,
    operations: after_base.operations,
    schemes: after_base.schemes,
    diagnostics: [
      {
        code: "ref-external",
        message: "external path is unsupported",
        location: { uri: "file:///orders.json", pointer: "/paths/~1external", },
      },
    ],
  }
  let comparison = @diff.compare(before, after)
  assert_false(comparison.complete)
  assert_eq(comparison.exit_code(), 2)
  assert_eq(comparison.changes[0].kind, @diff.Weakened)
  assert_true(comparison.changes[0].witness is Some(_))
}

///|
test "changed scheme configuration cannot silently compare as equivalent" {
  let before = document([{ "key": [] }])
  let new_schemes = before.schemes.map(fn(scheme) {
    @openapi.Scheme::{
      name: scheme.name,
      fingerprint: scheme.fingerprint + "changed",
      location: scheme.location,
    }
  })
  let after : @openapi.Document = {
    source: before.source,
    document_url: before.document_url,
    operations: before.operations.map(operation => {
      ..operation,
      scheme_identities: operation.scheme_identities.map(identity => {
        ..identity,
        fingerprint: identity.fingerprint + "changed",
      }),
    }),
    schemes: new_schemes,
    diagnostics: [],
  }
  let comparison = @diff.compare(before, after)
  assert_eq(comparison.exit_code(), 2)
  assert_eq(comparison.changes[0].kind, @diff.Incomparable)
  assert_eq(comparison.diagnostics[0].code, "scheme-incomparable")
}

///|
test "JSON SARIF and fatal failure reports are parseable and preserve witnesses" {
  let comparison = @diff.compare(
    document([{ "account": ["read", "write"] }]),
    document([{ "account": ["read"] }]),
  )
  let report = @json.parse(
    @diff.render_json(comparison),
    reject_duplicate_keys=true,
  )
  match report {
    {
      "schema_version": Number(1, ..),
      "complete": True,
      "exit_code": Number(1, ..),
      "changes": Array(
        [{ "kind": String("weakened"), "witness": Array(witness), .. }]
      ),
      ..
    } => assert_eq(witness.length(), 2)
    _ => fail("JSON report lost a regression")
  }
  let sarif = @json.parse(
    @diff.render_sarif(comparison),
    reject_duplicate_keys=true,
  )
  match sarif {
    {
      "version": String("2.1.0"),
      "runs": Array([{ "results": Array([result]), .. }]),
      ..
    } =>
      match result {
        {
          "ruleId": String("auth-regression"),
          "locations": Array(
            [{ "properties": { "jsonPointer": String(pointer), .. }, .. }]
          ),
          ..
        } => assert_true(pointer.contains("security"))
        _ => fail("SARIF result lost location")
      }
    _ => fail("invalid SARIF report")
  }
  let failure = @diff.failure_report([
    {
      code: "syntax",
      message: "invalid JSON",
      location: { uri: "file:///bad.json", pointer: "", },
    },
  ])
  assert_eq(failure.exit_code(), 2)
  assert_false(failure.complete)
  ignore(@json.parse(@diff.render_json(failure)))
  ignore(@json.parse(@diff.render_sarif(failure)))
}

///|
test "SARIF represents source labels without invalid physical URIs" {
  for source in ["<input>", "bad file name.json", "file:///bad%XX.json"] {
    let comparison = @diff.failure_report([
      {
        code: "syntax",
        message: "invalid input",
        location: { uri: source, pointer: "/paths", },
      },
    ])
    let sarif = @json.parse(@diff.render_sarif(comparison))
    match sarif {
      {
        "runs": Array(
          [
            {
              "invocations": Array(
                [
                  {
                    "toolExecutionNotifications": Array(
                      [{ "locations": Array([Object(location)]), .. }]
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
        assert_false(location.contains("physicalLocation"))
        assert_true(location.contains("logicalLocations"))
      }
      _ => fail("missing source location")
    }
  }
}

///|
test "duplicate operations in constructed documents are incomplete" {
  let before = document([])
  let after : @openapi.Document = {
    ..before,
    operations: [before.operations[0], before.operations[0]],
  }
  let comparison = @diff.compare(before, after)
  assert_eq(comparison.exit_code(), 2)
  assert_eq(comparison.changes.length(), 1)
  assert_true(
    comparison.diagnostics.any(fn(diagnostic) {
      diagnostic.code == "operation-duplicate"
    }),
  )
}
