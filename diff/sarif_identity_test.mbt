///|
fn identity_document(
  source : String,
  path : String,
  security : Json,
  verb~ : String = "get",
) -> @openapi.Document raise @openapi.DocumentError {
  let operation : Json = { "security": security }
  let paths = Json::object(
    Map([(path, Json::object(Map([(verb, operation)])))]),
  )
  @openapi.parse_document(template_spec(paths), format=@openapi.Json, source~)
}

///|
fn identity_comparison(
  source : String,
  path~ : String = "/orders/{id}",
  verb~ : String = "get",
) -> @diff.Comparison raise @openapi.DocumentError {
  @diff.compare(
    identity_document(
      "file:///baseline.json",
      path,
      [{ "Key": ["admin"] }],
      verb~,
    ),
    identity_document(source, path, [], verb~),
  )
}

///|
fn identity_run(
  comparison : @diff.Comparison,
  root~ : @diff.SarifSourceRoot? = None,
) -> Json raise {
  match @json.parse(@diff.render_sarif(comparison, source_root=root)) {
    { "runs": Array([run]), .. } => run
    _ => fail("SARIF must contain exactly one run")
  }
}

///|
fn identity_results(run : Json) -> Array[Json] raise {
  match run {
    { "results": Array(results), .. } => results
    _ => fail("SARIF run lost results")
  }
}

///|
fn identity_fingerprint(result : Json) -> String? raise {
  match result {
    {
      "partialFingerprints": {
        "oasAuthDiff/route/v1": String(route),
        "primaryLocationLineHash": String(primary),
        ..
      },
      ..
    } => {
      assert_eq(route, primary)
      assert_eq(route.length(), 64)
      assert_true(
        route
        .to_array()
        .all(c => {
          match c {
            '0'..<='9' | 'a'..<='f' => true
            _ => false
          }
        }),
      )
      Some(route)
    }
    Object(properties) if !properties.contains("partialFingerprints") => None
    _ => fail("SARIF fingerprint keys differ or have an invalid shape")
  }
}

///|
test "comparison preserves entry sources independently of deployment URLs and fatal reports" {
  let result = identity_comparison("file:///repo/api/after.json")
  assert_eq(result.before_source, Some("file:///baseline.json"))
  assert_eq(result.after_source, Some("file:///repo/api/after.json"))
  match @json.parse(@diff.render_json(result)) {
    {
      "schema_version": Number(1, ..),
      "document_sources": {
        "before": String("file:///baseline.json"),
        "after": String("file:///repo/api/after.json"),
        ..
      },
      "document_urls": { "before": Null, "after": Null, .. },
      ..
    } => ()
    _ => fail("JSON lost entry sources")
  }
  match identity_run(result) {
    {
      "properties": {
        "document_sources": {
          "before": String("file:///baseline.json"),
          "after": String("file:///repo/api/after.json"),
          ..
        },
        ..
      },
      ..
    } => ()
    _ => fail("SARIF lost entry sources")
  }
  let failure = @diff.failure_report([])
  assert_true(failure.before_source is None)
  assert_true(failure.after_source is None)
  match @json.parse(@diff.render_json(failure)) {
    { "document_sources": { "before": Null, "after": Null, .. }, .. } => ()
    _ => fail("fatal reports invented entry sources")
  }
}

///|
test "source root correlates equivalent POSIX and Windows checkouts with UTF8 route hashing" {
  let linux = identity_comparison(
    "file:///home/runner/repo/api/after.json",
    path="/订单/{id}",
  )
  let windows = identity_comparison(
    "file:///D:/work/repo/api/after.json",
    path="/订单/{order_id}",
  )
  let first = identity_fingerprint(
    identity_results(
      identity_run(
        linux,
        root=Some(@diff.SarifSourceRoot::new("file:///home/runner/repo/")),
      ),
    )[0],
  ).unwrap()
  let second = identity_fingerprint(
    identity_results(
      identity_run(
        windows,
        root=Some(@diff.SarifSourceRoot::new("file:///D:/work/repo/")),
      ),
    )[0],
  ).unwrap()
  assert_eq(first, second)
  // Independently computed from the specified JSON tuple using Python hashlib.
  assert_eq(
    first, "78e61ae1fae33af3dce34ce1e7ccab0a600a66c0d318db2d501fac5a83d93628",
  )
  assert_true(
    identity_fingerprint(identity_results(identity_run(linux))[0]) !=
    identity_fingerprint(identity_results(identity_run(windows))[0]),
  )
}

///|
test "parameter operationId witness and evidence changes retain one route fingerprint" {
  let root = Some(@diff.SarifSourceRoot::new("file:///repo/"))
  let original = identity_comparison("file:///repo/api/after.json")
  let baseline = identity_document(
    "file:///different/before.json",
    "/orders/{key}",
    [{ "Key": ["admin"] }],
  )
  let candidate = identity_document(
    "file:///repo/api/after.json",
    "/orders/{order_id}",
    [{ "Key": ["reader"] }],
  )
  let renamed : @openapi.Document = {
    ..candidate,
    operations: candidate.operations.map(operation => {
      ..operation,
      operation_id: Some("renamedOperation"),
      security_location: {
        uri: "file:///repo/shared/security.json",
        pointer: "/security",
      },
    }),
  }
  let changed = @diff.compare(baseline, renamed)
  assert_eq(original.changes[0].kind, @diff.Weakened)
  assert_eq(changed.changes[0].kind, @diff.Mixed)
  assert_true(original.changes[0].witness.unwrap().atoms().is_empty())
  assert_false(changed.changes[0].witness.unwrap().atoms().is_empty())
  let metadata : @diff.Comparison = {
    ..changed,
    before_document_url: Some("https://old.example/openapi.json"),
    after_document_url: Some("https://new.example/openapi.json"),
  }
  assert_eq(
    identity_fingerprint(identity_results(identity_run(original, root~))[0]),
    identity_fingerprint(identity_results(identity_run(metadata, root~))[0]),
  )
}

///|
test "shared global and external security locations cannot merge methods routes or entries" {
  let shared : @openapi.Location = {
    uri: "file:///repo/shared/security.json",
    pointer: "/security",
  }
  let root = Some(@diff.SarifSourceRoot::new("file:///repo/"))
  let base = identity_comparison("file:///repo/api/after.json")
  let first = base.changes[0]
  let multiple : @diff.Comparison = {
    ..base,
    changes: [
      { ..first, location: shared, },
      { ..first, http_method: "POST", location: shared, },
      { ..first, path: "/customers/{id}", location: shared, },
    ],
  }
  let results = identity_results(identity_run(multiple, root~))
  let fingerprints = results.map(identity_fingerprint)
  assert_eq(fingerprints.length(), 3)
  assert_true(fingerprints[0] != fingerprints[1])
  assert_true(fingerprints[0] != fingerprints[2])
  assert_true(fingerprints[1] != fingerprints[2])
  let another_entry : @diff.Comparison = {
    ..base,
    after_source: Some("file:///repo/other/after.json"),
    changes: [{ ..first, location: shared, }],
  }
  assert_true(
    fingerprints[0] !=
    identity_fingerprint(
      identity_results(identity_run(another_entry, root~))[0],
    ),
  )
  let addition : @diff.Comparison = {
    ..base,
    changes: [{ ..first, kind: @diff.Added, before: None, witness: None, }],
  }
  let added = identity_results(identity_run(addition, root~))[0]
  match added {
    { "ruleId": String("added-anonymous"), .. } => ()
    _ => fail("new anonymous route lost its rule")
  }
  assert_true(fingerprints[0] != identity_fingerprint(added))
}

///|
test "SARIF rewrites only physical evidence inside the supplied source root" {
  let root = Some(@diff.SarifSourceRoot::new("file:///repo/"))
  let comparison = identity_comparison("file:///repo/api/after.json")
  let with_diagnostic : @diff.Comparison = {
    ..comparison,
    complete: false,
    diagnostics: [
      {
        code: "example",
        message: "partial result",
        location: {
          uri: "file:///repo/shared/auth.json",
          pointer: "/components/securitySchemes/Key",
        },
      },
    ],
  }
  let original_json = @diff.render_json(with_diagnostic)
  let original_text = @diff.render_text(with_diagnostic)
  match identity_run(with_diagnostic, root~) {
    {
      "originalUriBaseIds": {
        "%SRCROOT%": { "uri": String("file:///repo/"), .. },
        ..
      },
      "results": Array(
        [
          {
            "locations": Array(
              [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": String("api/after.json"),
                      "uriBaseId": String("%SRCROOT%"),
                      ..
                    },
                    ..
                  },
                  "properties": {
                    "source": String("file:///repo/api/after.json"),
                    "jsonPointer": String("/paths/~1orders~1{id}/get/security"),
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
      "invocations": Array(
        [
          {
            "workingDirectory": { "uri": String("file:///repo/"), .. },
            "toolExecutionNotifications": Array(
              [
                {
                  "locations": Array(
                    [
                      {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": String("shared/auth.json"),
                            "uriBaseId": String("%SRCROOT%"),
                            ..
                          },
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
          },
        ]
      ),
      ..
    } => ()
    _ => fail("relative SARIF locations lost root mapping or original evidence")
  }
  assert_eq(@diff.render_json(with_diagnostic), original_json)
  assert_eq(@diff.render_text(with_diagnostic), original_text)
  let default_run = identity_run(comparison)
  match default_run {
    {
      "results": Array(
        [
          {
            "locations": Array(
              [
                {
                  "physicalLocation": {
                    "artifactLocation": Object(artifact),
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
    } => {
      assert_eq(artifact.get("uri"), Some(Json("file:///repo/api/after.json")))
      assert_false(artifact.contains("uriBaseId"))
    }
    _ => fail("default render changed absolute evidence")
  }
}

///|
test "root siblings different drives authorities and unsafe file URIs remain absolute" {
  let root = Some(@diff.SarifSourceRoot::new("file:///repo/"))
  for
    source in [
      "file:///repo2/api.json", "file:///D:/repo/api.json", "file://server/repo/api.json",
      "file:///repo/a%2Fb.json", "file:///repo/%2E%2E/outside.json", "https://example.test/repo/api.json",
    ] {
    let result = identity_comparison("file:///repo/api/after.json")
    let comparison : @diff.Comparison = {
      ..result,
      changes: [
        {
          ..result.changes[0],
          location: { uri: source, pointer: "/security", },
        },
      ],
    }
    match identity_results(identity_run(comparison, root~))[0] {
      {
        "locations": Array(
          [
            {
              "physicalLocation": { "artifactLocation": Object(artifact), .. },
              ..
            },
          ]
        ),
        ..
      } => {
        assert_eq(artifact.get("uri"), Some(Json(source)))
        assert_false(artifact.contains("uriBaseId"))
      }
      _ => fail("outside or unsafe source was rewritten")
    }
  }
}

///|
test "encoded file names retain URI meaning and a colon first segment stays relative" {
  let root = Some(@diff.SarifSourceRoot::new("file:///repo/"))
  for
    (source, relative) in [
      ("file:///repo/a:b.json", "./a:b.json"),
      ("file:///repo/a%23b%3fc%25.json", "a%23b%3Fc%25.json"),
      ("file:///repo/%e4%b8%ad%e6%96%87.json", "%E4%B8%AD%E6%96%87.json"),
    ] {
    let run = identity_run(identity_comparison(source), root~)
    match identity_results(run)[0] {
      {
        "locations": Array(
          [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": String(uri),
                  "uriBaseId": String("%SRCROOT%"),
                  ..
                },
                ..
              },
              ..
            },
          ]
        ),
        ..
      } => assert_eq(uri, relative)
      _ => fail("file name stopped being a relative URI")
    }
  }
}

///|
test "unverifiable entry sources omit fingerprints without guessing from security evidence" {
  let original = identity_comparison("file:///repo/api/after.json")
  for
    source in [
      None,
      Some("<input>"),
      Some("relative.json"),
      Some("https://example.test/openapi.json"),
      Some("https://[bad"),
      Some("file:///repo/bad%Q0.json"),
      Some("file:///repo/../api.json"),
      Some("file://server/repo/api.json"),
    ] {
    let comparison : @diff.Comparison = { ..original, after_source: source, }
    assert_true(
      identity_fingerprint(identity_results(identity_run(comparison))[0])
      is None,
    )
  }
  let labelled : @diff.Comparison = {
    ..original,
    after_source: Some("<input>"),
    changes: [
      {
        ..original.changes[0],
        location: { uri: "<input>", pointer: "/security", },
      },
    ],
  }
  match identity_results(identity_run(labelled))[0] {
    {
      "locations": Array(
        [
          {
            "logicalLocations": Array(
              [{ "fullyQualifiedName": String("<input>#/security"), .. }]
            ),
            ..
          },
        ]
      ),
      ..
    } => ()
    _ => fail("labelled evidence lost its logical location")
  }
}
