///|
fn endpoint_spec(
  endpoint : String,
  servers~ : Json = [{ "url": "https://api.example/v1/" }],
  paths~ : Json = { "/data": { "get": {} } },
  kind~ : String = "oauth2",
) -> String {
  let scheme : Json = if kind == "openIdConnect" {
    { "type": kind, "openIdConnectUrl": endpoint }
  } else {
    {
      "type": kind,
      "flows": {
        "clientCredentials": {
          "tokenUrl": endpoint,
          "scopes": { "read": "Read", "write": "Write" },
        },
      },
    }
  }
  let root : Json = {
    "openapi": "3.1.1",
    "servers": servers,
    "components": {
      "securitySchemes": {
        "OAuth": scheme,
        "Key": { "type": "http", "scheme": "bearer" },
      },
    },
    "security": [{ "OAuth": ["read"] }],
    "paths": paths,
  }
  root.stringify()
}

///|
fn endpoint_document(
  endpoint : String,
  servers~ : Json = [{ "url": "https://api.example/v1/" }],
  paths~ : Json = { "/data": { "get": {} } },
  kind~ : String = "oauth2",
  source~ : String = "file:///spec/openapi.json",
) -> @openapi.Document raise @openapi.DocumentError {
  @openapi.parse_document(
    endpoint_spec(endpoint, servers~, paths~, kind~),
    format=@openapi.Json,
    source~,
  )
}

///|
fn endpoint_change(
  result : @diff.Comparison,
  path : String,
) -> @diff.OperationChange {
  result.changes.iter().find_first(change => change.path == path).unwrap()
}

///|
test "absolute and equivalent relative OAuth and OpenID URLs describe the same identity" {
  for kind in ["oauth2", "openIdConnect"] {
    for
      (relative, base, absolute) in [
        (
          "oauth/token", "https://api.example/v1/", "https://api.example/v1/oauth/token",
        ),
        (
          "../oauth/token", "https://api.example/v1/", "https://api.example/oauth/token",
        ),
        (
          "/oauth/token", "https://api.example/v1/", "https://api.example/oauth/token",
        ),
        (
          "//identity.example/token", "https://api.example/v1/", "https://identity.example/token",
        ),
        (
          "?aud=api", "https://api.example/v1/token", "https://api.example/v1/token?aud=api",
        ),
      ] {
      let before = endpoint_document(absolute, kind~)
      let after = endpoint_document(relative, servers=[{ "url": base }], kind~)
      let result = @diff.compare(before, after)
      assert_true(result.complete)
      assert_eq(result.exit_code(), 0)
      assert_eq(result.changes[0].kind, @diff.Equivalent)
    }
  }
}

///|
test "absolute authentication endpoints do not depend on unrelated server variables" {
  let absolute = "https://identity.example/token"
  let before = endpoint_document(absolute)
  let server_choices : Array[Json] = [
    [{ "url": "https://elsewhere.example/base/" }],
    [{ "url": "/relative-api/" }],
    [
      {
        "url": "https://{tenant}.example/",
        "variables": { "tenant": { "default": "public" } },
      },
    ],
    [],
  ]
  for servers in server_choices {
    let after = endpoint_document(absolute, servers~)
    assert_eq(after.diagnostics.length(), 0)
    assert_eq(@diff.compare(before, after).exit_code(), 0)
  }
}

///|
test "authorization token and refresh endpoints all contribute to a flow identity" {
  let absolute =
    #|{"openapi":"3.1.1","servers":[{"url":"https://api.example/v1/"}],"components":{"securitySchemes":{"OAuth":{"type":"oauth2","flows":{"implicit":{"authorizationUrl":"https://api.example/authorize","scopes":{"read":"Read"}},"authorizationCode":{"authorizationUrl":"https://api.example/authorize","tokenUrl":"https://api.example/token","refreshUrl":"https://api.example/v1/refresh","scopes":{"read":"Read"}}}}}},"security":[{"OAuth":["read"]}],"paths":{"/data":{"get":{}}}}
  let relative = absolute
    .replace_all(old="https://api.example/authorize", new="../authorize")
    .replace_all(old="https://api.example/token", new="/token")
    .replace_all(old="https://api.example/v1/refresh", new="refresh")
  let before = @openapi.parse_document(absolute, format=@openapi.Json)
  let after = @openapi.parse_document(relative, format=@openapi.Json)
  assert_eq(after.diagnostics.length(), 0)
  assert_eq(@diff.compare(before, after).exit_code(), 0)
  for
    changed in [
      relative.replace_all(old="../authorize", new="../authorize-v2"),
      relative.replace_all(old="/token", new="/token-v2"),
      relative.replace_all(old="\"refresh\"", new="\"refresh-v2\""),
    ] {
    let result = @diff.compare(
      before,
      @openapi.parse_document(changed, format=@openapi.Json),
    )
    assert_eq(result.exit_code(), 2)
    assert_eq(result.changes[0].kind, @diff.Incomparable)
  }
}

///|
test "server precedence and shared components remain independent for each operation" {
  let paths : Json = {
    "/root": { "get": {} },
    "/path": { "servers": [{ "url": "https://path.example/base/" }], "get": {} },
    "/operation": {
      "servers": [{ "url": "https://path.example/base/" }],
      "get": { "servers": [{ "url": "https://operation.example/base/" }] },
    },
  }
  let before = endpoint_document("token", paths~)
  let after = endpoint_document("token", paths~, servers=[
    { "url": "https://changed.example/v2/" },
  ])
  let root_changed = @diff.compare(before, after)
  assert_eq(root_changed.exit_code(), 2)
  assert_eq(endpoint_change(root_changed, "/root").kind, @diff.Incomparable)
  assert_eq(endpoint_change(root_changed, "/path").kind, @diff.Equivalent)
  assert_eq(endpoint_change(root_changed, "/operation").kind, @diff.Equivalent)
  let changed_paths = @json.parse(
    paths
    .stringify()
    .replace_all(
      old="https://path.example/base/",
      new="https://new-path.example/base/",
    ),
  )
  let path_changed = @diff.compare(
    before,
    endpoint_document("token", paths=changed_paths),
  )
  assert_eq(endpoint_change(path_changed, "/root").kind, @diff.Equivalent)
  assert_eq(endpoint_change(path_changed, "/path").kind, @diff.Incomparable)
  assert_eq(endpoint_change(path_changed, "/operation").kind, @diff.Equivalent)
  let operation_changed = @diff.compare(
    before,
    endpoint_document(
      "token",
      paths=@json.parse(
        paths
        .stringify()
        .replace_all(
          old="https://operation.example/base/",
          new="https://new-operation.example/base/",
        ),
      ),
    ),
  )
  assert_eq(endpoint_change(operation_changed, "/root").kind, @diff.Equivalent)
  assert_eq(endpoint_change(operation_changed, "/path").kind, @diff.Equivalent)
  assert_eq(
    endpoint_change(operation_changed, "/operation").kind,
    @diff.Incomparable,
  )
}

///|
test "multiple server identities compare as a set without discarding changed members" {
  let a : Json = { "url": "https://a.example/api/" }
  let b : Json = { "url": "https://b.example/api/" }
  let c : Json = { "url": "https://c.example/api/" }
  let before = endpoint_document("token", servers=[a, b])
  assert_eq(
    @diff.compare(before, endpoint_document("token", servers=[b, a])).exit_code(),
    0,
  )
  assert_eq(
    @diff.compare(before, endpoint_document("token", servers=[a, b, a])).exit_code(),
    0,
  )
  for servers in [[a], [a, c], [a, b, c]] {
    let result = @diff.compare(
      before,
      endpoint_document("token", servers=Json::array(servers)),
    )
    assert_eq(result.exit_code(), 2)
    assert_eq(result.changes[0].kind, @diff.Incomparable)
  }
}

///|
fn tenant_server(values : Array[String], default_value : String) -> Json {
  {
    "url": "https://{tenant}.example/api/",
    "variables": {
      "tenant": {
        "default": default_value,
        "enum": Json::array(values.map(value => Json(value))),
      },
    },
  }
}

///|
test "finite variable domains and defaults participate in authentication identity" {
  let before = endpoint_document("token", servers=[
    tenant_server(["a", "b"], "a"),
  ])
  let reordered = endpoint_document("token", servers=[
    tenant_server(["b", "a", "a"], "a"),
  ])
  assert_eq(before.diagnostics.length(), 0)
  assert_eq(@diff.compare(before, reordered).exit_code(), 0)
  for
    server in [
      tenant_server(["a", "b", "c"], "a"),
      tenant_server(["a"], "a"),
      tenant_server(["a", "b"], "b"),
    ] {
    let result = @diff.compare(
      before,
      endpoint_document("token", servers=[server]),
    )
    assert_eq(result.exit_code(), 2)
    assert_eq(result.changes[0].kind, @diff.Incomparable)
  }
}

///|
test "invalid and unbounded server variables never become a complete default-only comparison" {
  let variable_choices : Array[Json] = [
    {},
    { "tenant": { "default": "a" } },
    { "tenant": { "enum": ["a"] } },
    { "tenant": { "default": "a", "enum": [] } },
    { "tenant": { "default": "a", "enum": ["b"] } },
    { "tenant": { "default": "a", "enum": ["a", 1] } },
  ]
  for variables in variable_choices {
    let document = endpoint_document("token", servers=[
      { "url": "https://{tenant}.example/api/", "variables": variables },
    ])
    assert_true(
      document.diagnostics.any(issue => {
        issue.code == "auth.variable" || issue.code == "auth.type"
      }),
    )
    assert_true(document.operations[0].policy is None)
    assert_eq(@diff.compare(document, document).exit_code(), 2)
  }
}

///|
test "variable combinations and server variable counts have explicit budgets" {
  let variables : Map[String, Json] = Map([])
  let names = []
  for index in 0..<17 {
    let name = "v" + index.to_string()
    names.push("{" + name + "}")
    variables[name] = { "default": "a", "enum": ["a"] }
  }
  let too_many_variables = endpoint_document("token", servers=[
    {
      "url": "https://api.example/" + names.join("/") + "/",
      "variables": Json::object(variables),
    },
  ])
  assert_eq(
    @diff.compare(too_many_variables, too_many_variables).exit_code(),
    2,
  )
  assert_true(too_many_variables.operations[0].policy is None)
  let too_many_variants = endpoint_document("token", servers=[
    {
      "url": "https://{tenant}.example/{version}/",
      "variables": {
        "tenant": {
          "default": "a",
          "enum": ["a", "b", "c", "d", "e", "f", "g", "h", "i"],
        },
        "version": {
          "default": "v1",
          "enum": ["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"],
        },
      },
    },
  ])
  assert_eq(@diff.compare(too_many_variants, too_many_variants).exit_code(), 2)
  assert_true(too_many_variants.operations[0].policy is None)
}

///|
test "large variable expansions and repeated endpoint identities remain bounded" {
  let large_value = String::make(9000, 'a')
  let expanded = endpoint_document("token", servers=[
    {
      "url": "https://api.example/{path}/",
      "variables": { "path": { "default": large_value, "enum": [large_value] } },
    },
  ])
  assert_true(expanded.diagnostics.length() > 0)
  assert_true(expanded.operations[0].policy is None)
  assert_eq(@diff.compare(expanded, expanded).exit_code(), 2)
  let paths : Map[String, Json] = Map([])
  for index in 0..<5000 {
    paths["/path-" + index.to_string()] = { "get": {} }
  }
  let repeated = endpoint_document(
    "https://identity.example/" + String::make(7000, 'a'),
    paths=Json::object(paths),
  )
  assert_true(repeated.diagnostics.length() > 0)
  assert_true(repeated.operations.any(operation => operation.policy is Some(_)))
  assert_true(repeated.operations.any(operation => operation.policy is None))
  assert_eq(@diff.compare(repeated, repeated).exit_code(), 2)
}

///|
test "relative servers use the HTTP document origin and never invent a file deployment origin" {
  let before = endpoint_document("https://docs.example/api/token")
  let served = endpoint_document(
    "token",
    servers=[{ "url": "../api/" }],
    source="https://docs.example/spec/openapi.json",
  )
  assert_eq(served.diagnostics.length(), 0)
  assert_eq(@diff.compare(before, served).exit_code(), 0)
  let file_based = endpoint_document("token", servers=[{ "url": "../api/" }])
  assert_true(file_based.diagnostics.any(issue => issue.code == "auth.base"))
  assert_true(file_based.operations[0].policy is None)
  assert_eq(@diff.compare(file_based, file_based).exit_code(), 2)
}

///|
test "referenced path servers resolve against their own declaration document" {
  let entry = endpoint_spec("token", paths={
    "/data": { "$ref": "parts/path.json" },
  })
  let loaded = @openapi.parse_with_loader(
    entry,
    format=@openapi.Json,
    source="https://entry.example/spec/openapi.json",
    load=(from, relative) => {
      if from != "https://entry.example/spec/openapi.json" ||
        relative != "parts/path.json" {
        raise @openapi.DocumentError("unexpected document request")
      }
      @openapi.SourceDocument::{
        source: "https://definitions.example/v1/path.json",
        format: @openapi.Json,
        text: "{\"servers\":[{\"url\":\"../api/\"}],\"get\":{}}",
      }
    },
  )
  let absolute = endpoint_document("https://definitions.example/api/token")
  assert_eq(loaded.diagnostics.length(), 0)
  assert_eq(@diff.compare(absolute, loaded).exit_code(), 0)
}

///|
test "empty server overrides use the default slash instead of inheriting another level" {
  let path_choices : Array[Json] = [
    { "/data": { "servers": [], "get": {} } },
    {
      "/data": {
        "servers": [{ "url": "https://wrong.example/" }],
        "get": { "servers": [] },
      },
    },
  ]
  for paths in path_choices {
    let actual = endpoint_document(
      "token",
      paths~,
      source="https://docs.example/spec/openapi.json",
    )
    let expected = endpoint_document("https://docs.example/token")
    assert_eq(actual.diagnostics.length(), 0)
    assert_eq(@diff.compare(expected, actual).exit_code(), 0)
  }
  let actual = endpoint_document(
    "token",
    servers=[],
    source="https://docs.example/spec/openapi.json",
  )
  assert_eq(
    @diff.compare(endpoint_document("https://docs.example/token"), actual).exit_code(),
    0,
  )
  assert_eq(
    @diff.compare(endpoint_document("token", servers=[]), actual).exit_code(),
    2,
  )
}

///|
test "invalid authentication URLs and server ports cannot produce successful comparisons" {
  for
    endpoint in [
      "ftp://identity.example/token", "//", "https://identity.example:65536/token",
      "https://identity.example:bad/token", "https://[::1/token", "/%QQ",
    ] {
    let invalid = endpoint_document(endpoint)
    assert_true(invalid.diagnostics.length() > 0)
    assert_true(invalid.operations[0].policy is None)
    assert_eq(@diff.compare(invalid, invalid).exit_code(), 2)
  }
  let invalid = endpoint_document("token", servers=[
    { "url": "https://api.example:65536/" },
  ])
  assert_true(invalid.operations[0].policy is None)
  assert_eq(@diff.compare(invalid, invalid).exit_code(), 2)
  let nondefault = endpoint_document("token", servers=[
    {
      "url": "https://api.example:{port}/",
      "variables": { "port": { "default": "443", "enum": ["443", "65536"] } },
    },
  ])
  assert_true(nondefault.operations[0].policy is None)
  assert_eq(@diff.compare(nondefault, nondefault).exit_code(), 2)
  let secondary = endpoint_document("token", servers=[
    { "url": "https://api.example/" },
    { "url": "https://api.example:bad/" },
  ])
  assert_true(secondary.operations[0].policy is None)
  assert_eq(@diff.compare(secondary, secondary).exit_code(), 2)
}

///|
test "a failed endpoint context preserves a verified regression on another operation" {
  let before_text = endpoint_spec("token", paths={
    "/broken": {
      "get": { "servers": [{ "url": "https://api.example:65536/" }] },
    },
    "/valid": { "get": { "security": [{ "Key": ["admin"] }] } },
  })
  let before = @openapi.parse_document(before_text, format=@openapi.Json)
  let after = @openapi.parse_document(
    before_text.replace_all(old="[\"admin\"]", new="[]"),
    format=@openapi.Json,
  )
  let result = @diff.compare(before, after)
  assert_false(result.complete)
  assert_eq(result.exit_code(), 2)
  let valid = endpoint_change(result, "/valid")
  assert_eq(valid.kind, @diff.Weakened)
  let witness = valid.witness.unwrap()
  assert_true(valid.after.unwrap().allows(witness))
  assert_false(valid.before.unwrap().allows(witness))
  assert_eq(endpoint_change(result, "/broken").kind, @diff.Incomparable)
}
