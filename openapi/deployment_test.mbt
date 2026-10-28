///|
fn deployment_spec(paths : Json) -> String {
  let root : Json = {
    "openapi": "3.1.1",
    "paths": paths,
    "security": [{ "OAuth": [] }],
    "components": {
      "securitySchemes": {
        "OAuth": {
          "type": "oauth2",
          "flows": {
            "clientCredentials": { "tokenUrl": "token", "scopes": {} },
          },
        },
      },
    },
  }
  root.stringify()
}

///|
test "document URLs supply origin without changing file evidence" {
  let text = deployment_spec({
    "/data": { "servers": [{ "url": "api/" }], "get": {} },
  })
  let document = @openapi.parse_document(
    text,
    format=@openapi.Json,
    source="file:///repo/spec.json",
    document_url=Some("HTTPS://DOCS.EXAMPLE:443/root/spec.json"),
  )
  assert_eq(document.document_url, Some("https://docs.example/root/spec.json"))
  assert_eq(document.source, "file:///repo/spec.json")
  assert_eq(document.operations[0].location.uri, "file:///repo/spec.json")
  assert_eq(document.diagnostics.length(), 0)
  assert_true(
    document.operations[0].scheme_identities[0].fingerprint.contains(
      "https://docs.example/root/api/token",
    ),
  )
  let legacy = @openapi.parse_document(
    text,
    format=@openapi.Json,
    source="HTTPS://DOCS.EXAMPLE:443/root/spec.json",
  )
  assert_eq(legacy.document_url, document.document_url)
  assert_eq(
    legacy.operations[0].scheme_identities[0].fingerprint,
    document.operations[0].scheme_identities[0].fingerprint,
  )
  let missing = @openapi.parse_document(
    text,
    format=@openapi.Json,
    source="file:///repo/spec.json",
  )
  assert_eq(missing.document_url, None)
  assert_eq(missing.diagnostics[0].code, "auth.base")
}

///|
test "invalid explicit document URL is fatal before external loading" {
  let root : Json = {
    "openapi": "3.1.1",
    "paths": { "/data": { "$ref": "child.json" } },
  }
  for
    url in [
      "relative/spec.json",
      "file:///repo/spec.json",
      "https://",
      "https://host:70000/spec.json",
      "https://docs.example/spec.json#part",
      "https://docs.example/" + String::make(8192, 'x'),
    ] {
    let calls : Array[String] = []
    try
      @openapi.parse_with_loader(
        root.stringify(),
        format=@openapi.Json,
        source="file:///repo/spec.json",
        document_url=Some(url),
        load=(_, path) => {
          calls.push(path)
          {
            text: "{\"get\":{}}",
            format: @openapi.Json,
            source: "file:///repo/child.json",
          }
        },
      )
    catch {
      error => assert_true(error.to_string().contains("file:///repo/spec.json"))
    } noraise {
      _ => fail("expected invalid document URL failure")
    }
    assert_eq(calls.length(), 0)
  }
}

///|
test "derived URL errors and raw URI budgets stop before invoking the loader" {
  for path in [String::make(8193, 'x') + ".json", "目录.json"] {
    let calls : Array[String] = []
    let document = @openapi.parse_with_loader(
      deployment_spec({ "/data": { "$ref": path } }),
      format=@openapi.Json,
      source="file:///repo/spec.json",
      document_url=Some("https://docs.example/spec.json"),
      load=(_, path) => {
        calls.push(path)
        {
          text: "{\"get\":{}}",
          format: @openapi.Json,
          source: "file:///repo/child.json",
        }
      },
    )
    assert_eq(calls.length(), 0)
    assert_eq(document.diagnostics[0].code, "ref.url")
  }
}

///|
test "raw escaped aliases cannot hide a conflicting deployment origin" {
  let calls : Array[String] = []
  let document = @openapi.parse_with_loader(
    deployment_spec({
      "/a": { "$ref": "parts%2Fchild.json" },
      "/b": { "$ref": "parts/child.json" },
      "/c": { "servers": [{ "url": "https://stable.example/api/" }], "get": {} },
    }),
    format=@openapi.Json,
    source="file:///repo/spec.json",
    document_url=Some("https://docs.example/root/spec.json"),
    load=(_, path) => {
      calls.push(path)
      {
        text: "{\"servers\":[{\"url\":\"api/\"}],\"get\":{}}",
        format: @openapi.Json,
        source: "file:///repo/parts/child.json",
      }
    },
  )
  assert_eq(calls.length(), 2)
  assert_eq(calls[0], "parts/child.json")
  assert_eq(calls[1], "parts/child.json")
  assert_true(document.diagnostics.any(item => item.code == "ref.conflict"))
  for operation in document.operations {
    if operation.path == "/a" {
      assert_true(operation.policy is None)
      assert_eq(operation.scheme_identities.length(), 0)
    } else {
      assert_eq(operation.path, "/c")
      assert_true(operation.policy is Some(_))
      assert_eq(operation.scheme_identities.length(), 1)
    }
  }
}
