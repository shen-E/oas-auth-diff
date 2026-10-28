///|
fn deployed_spec(
  paths : Json,
  servers~ : Json = [{ "url": "api/" }],
  security~ : Json = [{ "OAuth": ["read", "write"] }],
  endpoint~ : String = "token",
) -> String {
  let value : Json = {
    "openapi": "3.1.1",
    "servers": servers,
    "components": {
      "securitySchemes": {
        "OAuth": {
          "type": "oauth2",
          "flows": {
            "clientCredentials": {
              "tokenUrl": endpoint,
              "scopes": { "read": "Read", "write": "Write" },
            },
          },
        },
        "Absolute": {
          "type": "oauth2",
          "flows": {
            "clientCredentials": {
              "tokenUrl": "https://identity.example/token",
              "scopes": { "read": "Read", "write": "Write" },
            },
          },
        },
        "Key": { "type": "http", "scheme": "bearer" },
      },
    },
    "security": security,
    "paths": paths,
  }
  value.stringify()
}

///|
fn deployed_document(
  text : String,
  url : String?,
  source~ : String = "file:///repo/openapi.json",
) -> @openapi.Document raise @openapi.DocumentError {
  @openapi.parse_document(text, format=@openapi.Json, source~, document_url=url)
}

///|
fn deployed_sources(
  text : String,
  url : String?,
  sources : Map[String, @openapi.SourceDocument],
) -> @openapi.Document raise @openapi.DocumentError {
  @openapi.parse_with_loader(
    text,
    format=@openapi.Json,
    source="file:///repo/openapi.json",
    document_url=url,
    load=(from, path) => {
      match sources.get(from + "|" + path) {
        Some(source) => source
        None =>
          raise @openapi.DocumentError("Unexpected local document request")
      }
    },
  )
}

///|
fn deployed_change(
  comparison : @diff.Comparison,
  path : String,
  verb~ : String = "GET",
) -> @diff.OperationChange {
  comparison.changes
  .iter()
  .find_first(change => change.path == path && change.http_method == verb)
  .unwrap()
}

///|
test "an explicit document URL supplies deployment context without replacing file evidence" {
  let text = deployed_spec({ "/data": { "get": {} } }, servers=[
    { "url": "v1/" },
  ])
  let unknown = deployed_document(text, None)
  assert_eq(unknown.document_url, None)
  assert_true(unknown.diagnostics.any(issue => issue.code == "auth.base"))
  let deployed = deployed_document(
    text,
    Some("HTTPS://DOCS.example:443/spec/../api/openapi.json"),
  )
  assert_eq(
    deployed.document_url,
    Some("https://docs.example/api/openapi.json"),
  )
  assert_eq(deployed.source, "file:///repo/openapi.json")
  assert_eq(deployed.operations[0].location.uri, "file:///repo/openapi.json")
  assert_eq(
    deployed.operations[0].security_location.uri,
    "file:///repo/openapi.json",
  )
  let absolute = deployed_document(
    deployed_spec(
      { "/data": { "get": {} } },
      endpoint="https://docs.example/api/v1/token",
    ),
    None,
  )
  assert_eq(@diff.compare(absolute, deployed).exit_code(), 0)
  let changed = deployed_document(
    text,
    Some("https://other.example/api/openapi.json"),
  )
  assert_eq(@diff.compare(deployed, changed).exit_code(), 2)
}

///|
test "HTTP source fallback and explicit document URLs keep distinct identity and deployment roles" {
  let text = deployed_spec({ "/data": { "get": {} } }, servers=[
    { "url": "/api/" },
  ])
  let served = deployed_document(
    text,
    None,
    source="https://actual.example/spec.json",
  )
  assert_eq(served.document_url, Some("https://actual.example/spec.json"))
  let explicit = deployed_document(
    text,
    Some("https://expected.example/description.json"),
    source="https://actual.example/spec.json",
  )
  let expected = deployed_document(
    deployed_spec(
      { "/data": { "get": {} } },
      endpoint="https://expected.example/api/token",
    ),
    None,
  )
  assert_eq(explicit.source, "https://actual.example/spec.json")
  assert_eq(
    explicit.operations[0].location.uri,
    "https://actual.example/spec.json",
  )
  assert_eq(@diff.compare(expected, explicit).exit_code(), 0)
  assert_eq(@diff.compare(served, explicit).exit_code(), 2)
  let fixed = deployed_spec(
    { "/data": { "get": {} } },
    endpoint="https://identity.example/token",
  )
  assert_eq(
    @diff.compare(
      deployed_document(fixed, Some("https://one.example/spec.json")),
      deployed_document(fixed, Some("https://two.example/spec.json")),
    ).exit_code(),
    0,
  )
}

///|
test "deployed multi-file paths use the declaring document for relative servers" {
  let text = deployed_spec({ "/data": { "$ref": "parts/a.yaml#/item" } })
  let actual = deployed_sources(
    text,
    Some("https://docs.example/root/openapi.json"),
    {
      "file:///repo/openapi.json|parts/a.yaml": {
        source: "file:///repo/parts/a.yaml",
        format: @openapi.Yaml,
        text: "item:\n  $ref: '../shared/b.json#/item'\n",
      },
      "file:///repo/parts/a.yaml|../shared/b.json": {
        source: "file:///repo/shared/b.json",
        format: @openapi.Json,
        text: "{\"item\":{\"get\":{},\"post\":{\"servers\":[{\"url\":\"../v2/\"}]}}}",
      },
    },
  )
  let expected = deployed_document(
    deployed_spec({
      "/data": {
        "get": { "servers": [{ "url": "https://docs.example/root/api/" }] },
        "post": { "servers": [{ "url": "https://docs.example/root/v2/" }] },
      },
    }),
    None,
  )
  assert_eq(actual.diagnostics.length(), 0)
  assert_eq(actual.operations.length(), 2)
  assert_eq(@diff.compare(expected, actual).exit_code(), 0)
  for operation in actual.operations {
    assert_eq(operation.location.uri, "file:///repo/shared/b.json")
    assert_eq(operation.security_location.uri, "file:///repo/openapi.json")
  }
}

///|
test "escaped file separators remain escaped when deriving document deployment URLs" {
  let text = deployed_spec({ "/data": { "$ref": "parts%2Fchild.json#/item" } })
  let actual = deployed_sources(
    text,
    Some("https://docs.example/root/openapi.json"),
    {
      "file:///repo/openapi.json|parts/child.json": {
        source: "file:///repo/parts/child.json",
        format: @openapi.Json,
        text: "{\"item\":{\"servers\":[{\"url\":\"api/\"}],\"get\":{}}}",
      },
    },
  )
  let expected = deployed_document(
    deployed_spec(
      { "/data": { "get": {} } },
      endpoint="https://docs.example/root/api/token",
    ),
    None,
  )
  assert_eq(actual.diagnostics.length(), 0)
  assert_eq(@diff.compare(expected, actual).exit_code(), 0)
  assert_eq(actual.operations[0].location.uri, "file:///repo/parts/child.json")
}

///|
test "late deployment aliases invalidate dependent identities and preserve independent findings" {
  let text = deployed_spec({
    "/a-shared": { "$ref": "public/shared.json#/item" },
    "/independent": { "get": { "security": [{ "Key": ["admin"] }] } },
    "/z-shared": { "$ref": "private/shared.json#/item" },
  })
  let shared =
    #|{"item":{"servers":[{"url":"api/"}],"get":{"security":[{"OAuth":["read","write"]}]},"post":{"servers":[{"url":"https://stable.example/api/"}],"security":[{"OAuth":["read","write"]}]},"put":{"security":[{"Absolute":["read","write"]}]}}}
  let sources : Map[String, @openapi.SourceDocument] = {
    "file:///repo/openapi.json|public/shared.json": {
      source: "file:///repo/shared.json",
      format: @openapi.Json,
      text: shared,
    },
    "file:///repo/openapi.json|private/shared.json": {
      source: "file:///repo/shared.json",
      format: @openapi.Json,
      text: shared,
    },
  }
  let before = deployed_sources(
    text,
    Some("https://docs.example/root/openapi.json"),
    sources,
  )
  let after_sources : Map[String, @openapi.SourceDocument] = Map([])
  for key, source in sources {
    after_sources[key] = {
      ..source,
      text: source.text.replace_all(
        old="[\"read\",\"write\"]",
        new="[\"read\"]",
      ),
    }
  }
  let after = deployed_sources(
    text.replace_all(old="[\"admin\"]", new="[]"),
    Some("https://docs.example/root/openapi.json"),
    after_sources,
  )
  assert_true(before.diagnostics.any(issue => issue.code == "ref.conflict"))
  assert_true(after.diagnostics.any(issue => issue.code == "ref.conflict"))
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 2)
  let affected = deployed_change(result, "/a-shared")
  assert_eq(affected.kind, @diff.Incomparable)
  assert_true(affected.witness is None)
  assert_true(affected.before is None)
  assert_true(affected.after is None)
  for verb in ["POST", "PUT"] {
    let preserved = deployed_change(result, "/a-shared", verb~)
    assert_eq(preserved.kind, @diff.Weakened)
    let witness = preserved.witness.unwrap()
    assert_true(preserved.after.unwrap().allows(witness))
    assert_false(preserved.before.unwrap().allows(witness))
  }
  let independent = deployed_change(result, "/independent")
  assert_eq(independent.kind, @diff.Weakened)
  assert_true(independent.witness is Some(_))
}

///|
test "a late parent deployment conflict invalidates previously derived child origins" {
  let text = deployed_spec({
    "/a-chain": { "$ref": "public/parent.json#/item" },
    "/independent": { "get": { "security": [{ "Key": ["admin"] }] } },
    "/z-alias": { "$ref": "private/parent.json#/item" },
  })
  let parent : @openapi.SourceDocument = {
    source: "file:///repo/parent.json",
    format: @openapi.Json,
    text: "{\"item\":{\"$ref\":\"child.json#/item\"}}",
  }
  let sources : Map[String, @openapi.SourceDocument] = {
    "file:///repo/openapi.json|public/parent.json": parent,
    "file:///repo/openapi.json|private/parent.json": parent,
    "file:///repo/parent.json|child.json": {
      source: "file:///repo/child.json",
      format: @openapi.Json,
      text: "{\"item\":{\"servers\":[{\"url\":\"api/\"}],\"get\":{\"security\":[{\"OAuth\":[\"read\",\"write\"]}]}}}",
    },
  }
  let before = deployed_sources(
    text,
    Some("https://docs.example/root/openapi.json"),
    sources,
  )
  let after_sources = sources.copy()
  let child = sources["file:///repo/parent.json|child.json"]
  after_sources["file:///repo/parent.json|child.json"] = {
    ..child,
    text: child.text.replace_all(old="[\"read\",\"write\"]", new="[\"read\"]"),
  }
  let after = deployed_sources(
    text.replace_all(old="[\"admin\"]", new="[]"),
    Some("https://docs.example/root/openapi.json"),
    after_sources,
  )
  let result = @diff.compare(before, after)
  assert_true(result.diagnostics.any(issue => issue.code == "ref.conflict"))
  assert_eq(result.exit_code(), 2)
  let dependent = deployed_change(result, "/a-chain")
  assert_eq(dependent.kind, @diff.Incomparable)
  assert_true(dependent.witness is None)
  assert_true(dependent.before is None)
  assert_true(dependent.after is None)
  assert_eq(deployed_change(result, "/independent").kind, @diff.Weakened)
}

///|
test "deployment metadata is visible in reports while regression evidence retains the file URI" {
  let paths : Json = { "/data": { "get": {} } }
  let before_url = "https://docs.example/spec/v1/openapi.json"
  let after_url = "https://docs.example/spec/v2/openapi.json"
  let before = deployed_document(
    deployed_spec(paths, servers=[{ "url": "/api/" }]),
    Some(before_url),
    source="file:///repo/before.json",
  )
  let after = deployed_document(
    deployed_spec(paths, servers=[{ "url": "/api/" }], security=[
      { "OAuth": ["read"] },
    ]),
    Some(after_url),
    source="file:///repo/after.json",
  )
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.before_document_url, Some(before_url))
  assert_eq(result.after_document_url, Some(after_url))
  let json = @json.parse(@diff.render_json(result))
  match json {
    {
      "document_urls": { "before": String(old), "after": String(new), .. },
      "changes": Array(
        [
          {
            "location": { "uri": String(uri), "pointer": String(pointer), .. },
            ..
          },
        ]
      ),
      ..
    } => {
      assert_eq(old, before_url)
      assert_eq(new, after_url)
      assert_eq(uri, "file:///repo/after.json")
      assert_eq(pointer, "/security")
    }
    _ => fail("JSON report lost deployment context or file evidence")
  }
  let sarif = @json.parse(@diff.render_sarif(result))
  match sarif {
    {
      "runs": Array(
        [
          {
            "properties": {
              "document_urls": {
                "before": String(old),
                "after": String(new),
                ..
              },
              ..
            },
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
      assert_eq(old, before_url)
      assert_eq(new, after_url)
      assert_eq(uri, "file:///repo/after.json")
    }
    _ => fail("SARIF report lost deployment context or file evidence")
  }
  let text = @diff.render_text(result)
  assert_true(text.contains("Baseline document URL: " + before_url))
  assert_true(text.contains("Candidate document URL: " + after_url))
}

///|
test "invalid explicit document URLs fail even when authentication is absolute" {
  let text = deployed_spec(
    { "/data": { "get": {} } },
    endpoint="https://identity.example/token",
  )
  let urls = [
    "https://",
    "/openapi.json",
    "file:///repo/openapi.json",
    "https://user@docs.example/spec.json",
    "https://docs.example/spec.json#fragment",
    "https://docs.example:65536/spec.json",
    "https://docs.example/%QQ",
    "https://docs.example/" + String::make(9000, 'a'),
  ]
  for url in urls {
    try deployed_document(text, Some(url)) catch {
      _ => ()
    } noraise {
      _ => fail("expected an invalid explicit document URL to fail")
    }
  }
}
