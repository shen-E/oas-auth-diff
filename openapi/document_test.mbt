///|
fn parse(text : String) -> @openapi.Document raise @openapi.DocumentError {
  @openapi.parse_document(text, format=@openapi.Json, source="file:///api.json")
}

///|
fn policy(operation : @openapi.Operation) -> @logic.Policy raise {
  match operation.policy {
    Some(policy) => policy
    None => fail("expected an analyzed policy")
  }
}

///|
test "inherit security, explicit empty override and empty requirement are anonymous" {
  let document = parse(
    (
      #|{"openapi":"3.0.3","security":[{"Key":[]}],"components":{"securitySchemes":{"Key":{"type":"apiKey","name":"X-Key","in":"header"}}},"paths":{"/inherited":{"get":{}},"/empty":{"post":{"security":[]}},"/alternative":{"get":{"security":[{"Key":[]},{}]}}}}
    ),
  )
  assert_eq(document.diagnostics.length(), 0)
  assert_eq(document.operations.length(), 3)
  assert_true(policy(document.operations[0]).allows(@logic.GrantSet::new([])))
  assert_false(policy(document.operations[1]).allows(@logic.GrantSet::new([])))
  assert_true(policy(document.operations[2]).allows(@logic.GrantSet::new([])))
  assert_true(
    policy(document.operations[1]).allows(
      @logic.GrantSet::new([@logic.Credential("Key")]),
    ),
  )
  assert_eq(document.operations[1].security_location.pointer, "/security")
  assert_eq(document.operations[1].location.pointer, "/paths/~1inherited/get")
}

///|
test "requirements are OR, schemes and scopes are AND" {
  let document = parse(
    (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"A":{"type":"apiKey","name":"a","in":"query"},"B":{"type":"http","scheme":"basic"},"OAuth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://auth.example/token","scopes":{"read":"Read","write":"Write"}}}}}},"paths":{"/and":{"get":{"security":[{"A":[],"B":[]}]}},"/or":{"get":{"security":[{"A":[]},{"B":[]}]}},"/scopes":{"get":{"security":[{"OAuth":["read","write"]}]}}}}
    ),
  )
  assert_eq(document.diagnostics.length(), 0)
  let a = @logic.GrantSet::new([@logic.Credential("A")])
  assert_true(policy(document.operations[0]).allows(a))
  assert_false(policy(document.operations[1]).allows(a))
  let read = @logic.GrantSet::new([@logic.Scope("OAuth", "read")])
  assert_false(policy(document.operations[2]).allows(read))
  assert_true(
    policy(document.operations[2]).allows(
      @logic.GrantSet::new([
        @logic.Scope("OAuth", "read"),
        @logic.Scope("OAuth", "write"),
      ]),
    ),
  )
}

///|
test "OpenAPI 3.1 literal roles and 3.0 rejection retain unaffected operations" {
  let text =
    #|{"openapi":"3.1.0","components":{"securitySchemes":{"Bearer":{"type":"http","scheme":"bearer"}}},"paths":{"/admin":{"get":{"security":[{"Bearer":["admin"]}]}},"/public":{"get":{}}}}
  let newer = parse(text)
  assert_eq(newer.diagnostics.length(), 0)
  assert_false(
    policy(newer.operations[0]).allows(
      @logic.GrantSet::new([@logic.Credential("Bearer")]),
    ),
  )
  assert_true(
    policy(newer.operations[0]).allows(
      @logic.GrantSet::new([@logic.Role("Bearer", "admin")]),
    ),
  )
  let older = parse(text.replace_all(old="3.1.0", new="3.0.3"))
  assert_eq(older.diagnostics[0].code, "auth.role")
  assert_true(older.operations[0].policy is None)
  assert_true(policy(older.operations[1]).allows(@logic.GrantSet::new([])))
}

///|
test "JSON and YAML produce identical effective authorization" {
  let json = parse(
    (
      #|{"openapi":"3.1.1","security":[{"Key":[]}],"components":{"securitySchemes":{"Key":{"type":"apiKey","name":"X-Key","in":"header"}}},"paths":{"/pets":{"get":{},"post":{"security":[]}}},"example":{"big":9007199254740993}}
    ),
  )
  let yaml = @openapi.parse_document(
    (
      #|openapi: 3.1.1
      #|security:
      #|  - Key: []
      #|components:
      #|  securitySchemes:
      #|    Key:
      #|      type: apiKey
      #|      name: X-Key
      #|      in: header
      #|paths:
      #|  /pets:
      #|    get: {}
      #|    post:
      #|      security: []
      #|example:
      #|  big: 9007199254740993
    ),
    format=@openapi.Yaml,
  )
  assert_eq(yaml.diagnostics.length(), 0)
  assert_eq(json.operations.length(), yaml.operations.length())
  assert_eq(json.schemes[0].fingerprint, yaml.schemes[0].fingerprint)
  for index in 0..<json.operations.length() {
    assert_eq(json.operations[index].path, yaml.operations[index].path)
    assert_true(
      policy(json.operations[index]).implies(policy(yaml.operations[index])),
    )
    assert_true(
      policy(yaml.operations[index]).implies(policy(json.operations[index])),
    )
  }
}

///|
test "internal references decode percent and JSON Pointer escaping" {
  let document = parse(
    (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"Key":{"$ref":"#/x-definitions/A~1B~0C"}}},"x-definitions":{"A/B~C":{"type":"apiKey","in":"header","name":"X-Key"},"path item":{"get":{"security":[{"Key":[]}]}}},"paths":{"/pets":{"$ref":"#/x-definitions/path%20item"}}}
    ),
  )
  assert_eq(document.diagnostics.length(), 0)
  assert_eq(document.operations.length(), 1)
  assert_eq(
    document.operations[0].location.pointer,
    "/x-definitions/path item/get",
  )
  assert_eq(document.schemes[0].location.pointer, "/x-definitions/A~1B~0C")
  assert_false(policy(document.operations[0]).allows(@logic.GrantSet::new([])))
}

///|
test "array traversal in relevant reference" {
  let document = parse(
    (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"Key":{"$ref":"#/x-definitions/0"}}},"x-definitions":[{"type":"apiKey","in":"header","name":"X-Key"}],"paths":{"/pets":{"get":{"security":[{"Key":[]}]}}}}
    ),
  )
  assert_eq(document.diagnostics.length(), 0)
  assert_eq(document.schemes[0].location.pointer, "/x-definitions/0")
}

///|
test "external, circular, wrong target and conflicting references diagnose incompleteness" {
  for
    (reference, expected) in [
      ("other.yaml#/Key", "ref.external"),
      ("https://example.invalid/api.yaml#/Key", "ref.external"),
      ("#/components/securitySchemes/Key", "ref.cycle"),
      ("#/paths", "auth.required"),
      ("#/missing", "ref.missing"),
      ("#/bad~2key", "ref.pointer"),
      ("#/bad%QQ", "ref.pointer"),
    ] {
    let document = parse(
      "{\"openapi\":\"3.1.1\",\"components\":{\"securitySchemes\":{\"Key\":{\"$ref\":" +
      Json::string(reference).stringify() +
      "}}},\"paths\":{\"/pets\":{\"get\":{\"security\":[{\"Key\":[]}]}}}}",
    )
    assert_eq(document.diagnostics[0].code, expected)
    assert_true(document.operations[0].policy is None)
  }
  let conflict = parse(
    (
      #|{"openapi":"3.1.1","paths":{"/pets":{"$ref":"#/x-item","get":{}}},"x-item":{"post":{}}}
    ),
  )
  assert_eq(conflict.diagnostics[0].code, "ref.sibling")
}

///|
test "unrelated external response refs and invalid unused schemes are ignored" {
  let document = parse(
    (
      #|{"openapi":"3.0.3","components":{"securitySchemes":{"Unused":{"$ref":"https://example.invalid/unused.yaml"},"Good":{"type":"http","scheme":"basic"}}},"paths":{"/pets":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"other.yaml#/Pets"}}}}}}}}}
    ),
  )
  assert_eq(document.diagnostics.length(), 0)
  assert_eq(document.schemes.length(), 1)
  assert_eq(document.schemes[0].name, "Good")
  assert_true(policy(document.operations[0]).allows(@logic.GrantSet::new([])))
}

///|
test "scheme fingerprints ignore presentation and retain credential endpoints" {
  let before = parse(
    (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"Bearer":{"type":"http","scheme":"Bearer","bearerFormat":"JWT","description":"Old"},"OAuth":{"type":"oauth2","flows":{"implicit":{"authorizationUrl":"https://auth.example/authorize","scopes":{"read":"Old"}}}}}},"paths":{}}
    ),
  )
  let after = parse(
    (
      #|{"paths":{},"components":{"securitySchemes":{"OAuth":{"flows":{"implicit":{"scopes":{"read":"New"},"authorizationUrl":"https://auth.example/authorize"}},"type":"oauth2"},"Bearer":{"description":"New","type":"http","scheme":"bearer","bearerFormat":"Opaque"}}},"openapi":"3.1.1"}
    ),
  )
  assert_eq(before.schemes[0].fingerprint, after.schemes[0].fingerprint)
  assert_eq(before.schemes[1].fingerprint, after.schemes[1].fingerprint)
  let changed = parse(
    (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"OAuth":{"type":"oauth2","flows":{"implicit":{"authorizationUrl":"https://other.example/authorize","scopes":{"read":"Old"}}}}}},"paths":{}}
    ),
  )
  assert_false(before.schemes[1].fingerprint == changed.schemes[0].fingerprint)
}

///|
test "invalid auth structure is never treated as anonymous" {
  for
    fragment in [
      "null", "{}", "[null]", "[{\"Missing\":[]}]", "[{\"Missing\":\"read\"}]",
    ] {
    let document = parse(
      "{\"openapi\":\"3.1.1\",\"paths\":{\"/pets\":{\"get\":{\"security\":" +
      fragment +
      "}}}}",
    )
    assert_true(document.diagnostics.length() > 0)
    assert_true(document.operations[0].policy is None)
  }
}

///|
test "relative authentication endpoints are explicit unsupported analysis" {
  for endpoint in ["/token", "../token", "//auth.example/token", "https://"] {
    let document = parse(
      "{\"openapi\":\"3.1.1\",\"components\":{\"securitySchemes\":{\"OAuth\":{\"type\":\"oauth2\",\"flows\":{\"clientCredentials\":{\"tokenUrl\":" +
      Json::string(endpoint).stringify() +
      ",\"scopes\":{}}}}}},\"paths\":{\"/pets\":{\"get\":{\"security\":[{\"OAuth\":[]}]}}}}",
    )
    assert_eq(document.diagnostics[0].code, "auth.url")
    assert_true(document.operations[0].policy is None)
  }
}

///|
test "scheme required fields, OAuth scopes and operation references fail closed" {
  let invalid_scheme = parse(
    (
      #|{"openapi":"3.1.1","components":{"securitySchemes":{"OAuth":{"type":"oauth2","flows":{"password":{"tokenUrl":"https://auth.example/token","scopes":{"read":"Read"}}}}}},"paths":{"/pets":{"get":{"security":[{"OAuth":["undefined"]}]}}}}
    ),
  )
  assert_eq(invalid_scheme.diagnostics[0].code, "auth.scope")
  assert_true(invalid_scheme.operations[0].policy is None)
  let reference = parse(
    (
      #|{"openapi":"3.1.1","paths":{"/pets":{"get":{"$ref":"other.yaml#/operation"}}}}
    ),
  )
  assert_eq(reference.diagnostics[0].code, "auth.operation")
  assert_true(reference.operations[0].policy is None)
  for
    definition in [
      "{}", "{\"type\":\"apiKey\",\"in\":\"header\"}", "{\"type\":\"http\",\"scheme\":null}",
      "{\"type\":\"oauth2\",\"flows\":{}}",
    ] {
    let document = parse(
      "{\"openapi\":\"3.1.1\",\"components\":{\"securitySchemes\":{\"Key\":" +
      definition +
      "}},\"paths\":{\"/pets\":{\"get\":{\"security\":[{\"Key\":[]}]}}}}",
    )
    assert_true(document.diagnostics.length() > 0)
    assert_true(document.operations[0].policy is None)
  }
}

///|
test "operation refs fail before anonymous inheritance or explicit security across encodings" {
  let cases = [
    (
      @openapi.Json,
      (
        #|{"openapi":"3.1.1","components":{"securitySchemes":{"Key":{"type":"http","scheme":"bearer"}}},"paths":{"/broken":{"get":{"$ref":"external.yaml#/operation","security":[]}},"/valid":{"post":{"security":[{"Key":[]}],"requestBody":{"$ref":"external.yaml#/Request"},"responses":{"200":{"$ref":"external.yaml#/Response"}}}}}}
      ),
    ),
    (
      @openapi.Yaml,
      (
        #|openapi: 3.1.1
        #|components:
        #|  securitySchemes:
        #|    Key:
        #|      type: http
        #|      scheme: bearer
        #|paths:
        #|  /broken:
        #|    get:
        #|      $ref: external.yaml#/operation
        #|      security: []
        #|  /valid:
        #|    post:
        #|      security:
        #|        - Key: []
        #|      requestBody:
        #|        $ref: external.yaml#/Request
        #|      responses:
        #|        '200':
        #|          $ref: external.yaml#/Response
      ),
    ),
  ]
  for (format, text) in cases {
    let document = @openapi.parse_document(text, format~)
    assert_eq(document.operations.length(), 2)
    assert_eq(document.diagnostics.length(), 1)
    assert_eq(document.diagnostics[0].code, "auth.operation")
    assert_eq(
      document.diagnostics[0].location.pointer,
      "/paths/~1broken/get/$ref",
    )
    for operation in document.operations {
      if operation.path == "/broken" {
        assert_true(operation.policy is None)
      } else {
        assert_false(policy(operation).allows(@logic.GrantSet::new([])))
        assert_true(
          policy(operation).allows(
            @logic.GrantSet::new([@logic.Credential("Key")]),
          ),
        )
      }
    }
  }
}
