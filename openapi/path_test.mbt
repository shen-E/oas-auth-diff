///|
test "path identities replace template names and preserve literal routing text" {
  let cases = [
    ("/", "/"),
    ("/orders/{id}", "/orders/{}"),
    ("/orders/{order_id}", "/orders/{}"),
    ("/files/{name}.{ext}", "/files/{}.{}"),
    ("/{甲}/{乙}", "/{}/{}"),
    ("/literal/%7Bid%7D/{id}/", "/literal/%7Bid%7D/{}/"),
    ("/a//{first}{second}", "/a//{}{}"),
  ]
  for (path, expected) in cases {
    assert_eq(@openapi.path_identity(path), Some(expected))
  }
  let distinct = [
    ("/orders/{id}", "/Orders/{id}"),
    ("/orders/{id}", "/orders/{id}/"),
    ("/orders/{id}", "/orders//{id}"),
    ("/orders/%2f/{id}", "/orders/%2F/{id}"),
    ("/orders/{id}", "/purchases/{id}"),
    ("/orders/{id}", "/orders/id"),
  ]
  for (first, second) in distinct {
    assert_false(
      @openapi.path_identity(first) == @openapi.path_identity(second),
    )
  }
}

///|
test "path identities reject malformed braces without interpreting encoded literals" {
  for
    path in [
      "", "orders/{id}", "{id}", "/{}", "/a/{id", "/a/id}", "/a/{{id}}", "/a/{id/name}",
      "/a/{id}/{}", "/a/{id}}", "/a/{id}{", "/a/{a{b}",
    ] {
    assert_eq(@openapi.path_identity(path), None)
  }
  assert_eq(@openapi.path_identity("/a/%7B%7D"), Some("/a/%7B%7D"))
}

///|
test "duplicate path identities are all rejected before loading even across methods" {
  let calls : Array[String] = []
  let document = @openapi.parse_with_loader(
    (
      #|{"openapi":"3.1.1","paths":{"/orders/{id}":{"$ref":"missing-get.yaml"},"/orders/{order_id}":{"post":{}},"/orders/{key}":{"$ref":"missing-put.yaml"},"/orders/id":{"get":{}},"x-not-a-path":{"$ref":"unused.yaml"}}}
    ),
    format=@openapi.Json,
    source="file:///entry.json",
    load=(_, path) => {
      calls.push(path)
      raise @openapi.DocumentError("must not load conflicting paths")
    },
  )
  assert_eq(calls.length(), 0)
  assert_eq(document.operations.length(), 1)
  assert_eq(document.operations[0].path, "/orders/id")
  assert_eq(document.diagnostics.length(), 3)
  for item in document.diagnostics {
    assert_eq(item.code, "path-duplicate")
    assert_eq(item.location.uri, "file:///entry.json")
    assert_true(item.location.pointer.has_prefix("/paths/~1orders~1{"))
  }
}

///|
test "invalid path templates are diagnosed before reference resolution" {
  let calls : Array[String] = []
  let document = @openapi.parse_with_loader(
    (
      #|{"openapi":"3.0.3","paths":{"missing-slash":{"$ref":"missing.yaml"},"/empty/{}":{"$ref":"missing.yaml"},"/broken/{id":{"$ref":"missing.yaml"},"/cross/{id/name}":{"$ref":"missing.yaml"},"/valid/{id}":{"get":{}}}}
    ),
    format=@openapi.Json,
    source="file:///entry.json",
    load=(_, path) => {
      calls.push(path)
      raise @openapi.DocumentError("must not load invalid paths")
    },
  )
  assert_eq(calls.length(), 0)
  assert_eq(document.operations.length(), 1)
  assert_eq(document.operations[0].path, "/valid/{id}")
  assert_eq(document.diagnostics.length(), 4)
  for item in document.diagnostics {
    assert_eq(item.code, "auth.path")
  }
}

///|
test "paired renamed templates supplement peer-required schemes without rewriting raw paths" {
  let before : @openapi.SourceDocument = {
    text: (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"A":{"type":"http","scheme":"basic"},"B":{"$ref":"b.yaml#/B"}}},"paths":{"/orders/{id}":{"get":{"security":[{"A":[],"B":[]}]}}}}
    ),
    format: @openapi.Json,
    source: "file:///before.json",
  }
  let after : @openapi.SourceDocument = {
    text: (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"A":{"type":"http","scheme":"basic"},"B":{"$ref":"b.yaml#/B"}}},"paths":{"/orders/{order_id}":{"get":{"security":[{"A":[]}]}}}}
    ),
    format: @openapi.Json,
    source: "file:///after.json",
  }
  let calls : Array[String] = []
  let pair = @openapi.parse_pair(
    before,
    after,
    before_load=Some((from, path) => {
      calls.push(from + ":" + path)
      {
        text: "B: {type: http, scheme: bearer}",
        format: @openapi.Yaml,
        source: "file:///before-b.yaml",
      }
    }),
    after_load=Some((from, path) => {
      calls.push(from + ":" + path)
      {
        text: "B: {type: http, scheme: bearer}",
        format: @openapi.Yaml,
        source: "file:///after-b.yaml",
      }
    }),
  )
  assert_eq(calls.length(), 2)
  assert_eq(pair.before.diagnostics.length(), 0)
  assert_eq(pair.after.diagnostics.length(), 0)
  assert_eq(pair.before.operations[0].path, "/orders/{id}")
  assert_eq(pair.after.operations[0].path, "/orders/{order_id}")
  assert_eq(pair.before.operations[0].scheme_identities.length(), 2)
  assert_eq(pair.after.operations[0].scheme_identities.length(), 2)
  assert_eq(
    pair.before.operations[0].location.pointer,
    "/paths/~1orders~1{id}/get",
  )
  assert_eq(
    pair.after.operations[0].location.pointer,
    "/paths/~1orders~1{order_id}/get",
  )
}
