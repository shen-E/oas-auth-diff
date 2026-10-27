///|
fn server_document(
  servers : Json,
  paths : Json,
  schemes : Json,
  security : Json,
) -> @openapi.Document raise {
  let root : Json = {
    "openapi": "3.1.1",
    "servers": servers,
    "paths": paths,
    "components": { "securitySchemes": schemes },
    "security": security,
  }
  @openapi.parse_document(
    root.stringify(),
    format=@openapi.Json,
    source="file:///api.json",
  )
}

///|
test "all OAuth endpoints remain grouped by the same effective server" {
  let document = server_document(
    [
      { "url": "https://one.example/api/" },
      { "url": "https://two.example/api/" },
    ],
    { "/data": { "get": {} } },
    {
      "OAuth": {
        "type": "oauth2",
        "flows": {
          "authorizationCode": {
            "authorizationUrl": "authorize",
            "tokenUrl": "token",
            "refreshUrl": "refresh",
            "scopes": {},
          },
        },
      },
    },
    [{ "OAuth": [] }],
  )
  assert_eq(document.diagnostics.length(), 0)
  let identity = document.operations[0].scheme_identities[0]
  let variants = match @json.parse(identity.fingerprint) {
    { "variants": Array(variants), .. } => variants
    _ => fail("expected instantiated endpoint variants")
  }
  assert_eq(variants.length(), 2)
  for variant in variants {
    match variant {
      {
        "configuration": {
          "flows": {
            "authorizationCode": {
              "authorizationUrl": String(authorize),
              "tokenUrl": String(token),
              "refreshUrl": String(refresh),
              ..
            },
            ..
          },
          ..
        },
        ..
      } => {
        let base = if authorize.has_prefix("https://one.example/") {
          "https://one.example/api/"
        } else {
          "https://two.example/api/"
        }
        assert_eq(authorize, base + "authorize")
        assert_eq(token, base + "token")
        assert_eq(refresh, base + "refresh")
      }
      _ => fail("expected one complete flow tuple per server")
    }
  }
}

///|
test "used identity tuple budget counts cached operation expansion" {
  let servers = Json(
    Array::makei(64, index => {
      let value : Json = {
        "url": "https://auth.example/api/" + index.to_string() + "/",
      }
      value
    }),
  )
  let paths : Map[String, Json] = Map([])
  for index in 0..<2000 {
    paths["/item/" + index.to_string()] = { "get": {} }
  }
  let document = server_document(
    servers,
    Json(paths),
    {
      "OAuth": {
        "type": "oauth2",
        "flows": { "clientCredentials": { "tokenUrl": "token", "scopes": {} } },
      },
    },
    [{ "OAuth": [] }],
  )
  assert_true(
    document.diagnostics.any(item => item.code == "resource.identities"),
  )
  assert_eq(
    document.operations
    .filter(operation => operation.policy is Some(_))
    .length(),
    1562,
  )
  assert_eq(document.operations.length(), 2000)
}

///|
test "identity metadata is bounded before tuples expand and unused failures stay quiet" {
  let values = Array::makei(64, index => {
    index.to_string() + String::make(7900, 'a')
  })
  let servers : Json = [
    {
      "url": "https://auth.example/{part}/",
      "variables": { "part": { "default": values[0], "enum": Json(values) } },
    },
  ]
  let schemes : Json = {
    "Key": { "type": "http", "scheme": "basic" },
    "OAuth": {
      "type": "oauth2",
      "flows": { "clientCredentials": { "tokenUrl": "token", "scopes": {} } },
    },
  }
  let used = server_document(servers, { "/data": { "get": {} } }, schemes, [
    { "OAuth": [] },
  ])
  assert_true(used.diagnostics.any(item => item.code == "resource.identities"))
  assert_true(used.operations[0].policy is None)
  let unused = server_document(
    servers,
    { "/a": { "get": {} }, "/b": { "get": {} } },
    schemes,
    [{ "Key": [] }],
  )
  assert_eq(unused.diagnostics.length(), 0)
  for operation in unused.operations {
    assert_true(operation.policy is Some(_))
    assert_eq(operation.scheme_identities.length(), 1)
    assert_eq(operation.scheme_identities[0].name, "Key")
  }
}

///|
test "authentication URI byte limit is enforced before operation identities" {
  let endpoint = "https://auth.example/" + String::make(8192, 'a')
  let document = server_document(
    [],
    { "/data": { "get": {} } },
    {
      "OAuth": {
        "type": "oauth2",
        "flows": { "clientCredentials": { "tokenUrl": endpoint, "scopes": {} } },
      },
    },
    [{ "OAuth": [] }],
  )
  assert_true(
    document.diagnostics.any(item => item.code == "resource.identities"),
  )
  assert_true(document.operations[0].policy is None)
}
