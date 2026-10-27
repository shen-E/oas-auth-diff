///|
fn parsed(text : String) -> @openapi.Document raise {
  @openapi.parse_document(text, format=@openapi.Json)
}

///|
test "relative OAuth endpoint base changes require incomplete comparison" {
  let text =
    #|{"openapi":"3.1.1","servers":[{"url":"https://trusted.example"}],"security":[{"OAuth":[]}],"components":{"securitySchemes":{"OAuth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"/token","scopes":{}}}}}},"paths":{"/data":{"get":{}}}}
  let before = parsed(text)
  let after = parsed(
    text.replace_all(old="trusted.example", new="other.example"),
  )
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 2)
}

///|
test "role removal, inherited anonymous and reference paths retain evidence" {
  let text =
    #|{"openapi":"3.1.1","components":{"securitySchemes":{"Bearer":{"type":"http","scheme":"bearer"}}},"security":[{"Bearer":["admin"]}],"paths":{"/inherited":{"$ref":"#/x-item"},"/override":{"get":{"security":[{}]}}},"x-item":{"get":{}}}
  let before = parsed(text)
  let after = parsed(text.replace_all(old="[\"admin\"]", new="[]"))
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 1)
  let inherited = result.changes
    .iter()
    .find_first(change => change.path == "/inherited")
    .unwrap()
  let overridden = result.changes
    .iter()
    .find_first(change => change.path == "/override")
    .unwrap()
  assert_eq(inherited.kind, @diff.Weakened)
  assert_eq(overridden.kind, @diff.Equivalent)
  let grants = inherited.witness.unwrap()
  assert_true(inherited.after.unwrap().allows(grants))
  assert_false(inherited.before.unwrap().allows(grants))
}

///|
test "partial broken refs do not discard independent demonstrated regressions" {
  let text =
    #|{"openapi":"3.1.1","components":{"securitySchemes":{"Key":{"type":"apiKey","name":"X-Key","in":"header"}}},"paths":{"/valid":{"get":{"security":[{"Key":[]}]}},"/broken":{"$ref":"https://example.invalid/path"}}}
  let before = parsed(text)
  let after = parsed(text.replace_all(old="[{\"Key\":[]}]", new="[]"))
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 2)
  assert_true(
    result.changes.any(change => {
      change.kind == @diff.Weakened && change.witness is Some(_)
    }),
  )
}

///|
fn formula_document(alternatives_mask : Int32) -> String {
  let alternatives : Array[Json] = []
  for clause in 0..<4 {
    if (alternatives_mask & (1 << clause)) != 0 {
      let requirement : Map[String, Json] = Map([])
      if (clause & 1) != 0 {
        requirement["A"] = []
      }
      if (clause & 2) != 0 {
        requirement["B"] = []
      }
      alternatives.push(Json::object(requirement))
    }
  }
  let root : Json = {
    "openapi": "3.1.1",
    "components": {
      "securitySchemes": {
        "A": { "type": "apiKey", "in": "header", "name": "X-A" },
        "B": { "type": "apiKey", "in": "header", "name": "X-B" },
      },
    },
    "paths": { "/data": { "get": { "security": Json::array(alternatives) } } },
  }
  root.stringify()
}

///|
fn direct_truth(alternatives_mask : Int32) -> Int32 {
  if alternatives_mask == 0 {
    return 15
  } // OpenAPI's empty list removes auth.
  let mut truth = 0
  for grants in 0..<4 {
    let mut allowed = false
    for clause in 0..<4 {
      if (alternatives_mask & (1 << clause)) != 0 && (clause & grants) == clause {
        allowed = true
      }
    }
    if allowed {
      truth = truth | (1 << grants)
    }
  }
  truth
}

///|
test "all two-scheme declarations agree with independent OpenAPI truth tables" {
  let docs = Array::makei(16, mask => parsed(formula_document(mask)))
  for old_mask in 0..<16 {
    for new_mask in 0..<16 {
      let old_truth = direct_truth(old_mask)
      let new_truth = direct_truth(new_mask)
      let expected = if (old_truth & new_truth) == new_truth { 0 } else { 1 }
      let result = @diff.compare(docs[old_mask], docs[new_mask])
      assert_eq(result.exit_code(), expected)
    }
  }
}

///|
test "public incomplete added operations never receive success" {
  let empty = parsed("{\"openapi\":\"3.1.1\",\"paths\":{}}")
  let base = parsed(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/data\":{\"get\":{}}}}",
  )
  let previous = base.operations[0]
  let invalid : @openapi.Document = {
    ..base,
    operations: [{ ..previous, policy: None, }],
  }
  let result = @diff.compare(empty, invalid)
  assert_eq(result.exit_code(), 2)
}
