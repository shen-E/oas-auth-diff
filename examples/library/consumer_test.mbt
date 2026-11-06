///|
test "authorization policies produce an independently evaluated permission witness" {
  let before = @logic.Policy::new([
    [Credential("account"), Scope("account", "read"), Scope("account", "write")],
  ])
  let after = @logic.Policy::new([
    [Credential("account"), Scope("account", "read")],
  ])
  let witness = after.witness_against(before).unwrap()
  assert_true(after.allows(witness))
  assert_false(before.allows(witness))
  assert_true(before.implies(after))
}

///|
test "Schema inclusion supplies a request value for review" {
  let before = @schema.parse({ "type": "string", "pattern": "^[一-龥]+$" })
  let after = @schema.parse({ "type": "string", "pattern": "^猫+$" })
  assert_true(@schema.subset(after, before) is Included)
  match @schema.subset(before, after) {
    Excluded(value) => {
      assert_true(before.accepts(value))
      assert_false(after.accepts(value))
    }
    _ => fail("expected a concrete request counterexample")
  }
}

///|
test "OpenAPI consumers can resolve static Schema anchors" {
  let resolver = @openapi.ReferenceResolver::new({
    source: "file:///api.json",
    format: @openapi.Json,
    text: "{\"$defs\":{\"Id\":{\"$anchor\":\"Id\",\"type\":\"integer\"}}}",
  })
  match resolver.resolve_schema("#Id", { uri: resolver.source, pointer: "", }) {
    Ok((_, at)) => assert_eq(at.pointer, "/$defs/Id")
    Err(diagnostic) => fail(diagnostic.message)
  }
}

///|
test "authorization document comparison renders structured results" {
  let text = "{\"openapi\":\"3.1.1\",\"components\":{\"securitySchemes\":{\"Account\":{\"type\":\"http\",\"scheme\":\"bearer\"}}},\"security\":[{\"Account\":[]}],\"paths\":{\"/orders\":{\"get\":{}}}}"
  let before = @openapi.parse_document(text, format=@openapi.Json)
  let after = @openapi.parse_document(
    text.replace_all(old="[{\"Account\":[]}]", new="[]"),
    format=@openapi.Json,
  )
  let result = @diff.compare(before, after)
  assert_eq(result.exit_code(), 1)
  assert_true(@diff.render_json(result).contains("\"weakened\""))
}

///|
test "compatibility comparison retains data witnesses" {
  let text = "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"post\":{\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"type\":\"string\",\"enum\":[\"draft\",\"ready\"]}}}}}}}}"
  let before = @openapi.parse_specification(text, format=@openapi.Json)
  let after = @openapi.parse_specification(
    text.replace_all(old="[\"draft\",\"ready\"]", new="[\"ready\"]"),
    format=@openapi.Json,
  )
  let result = @compat.compare(before, after)
  assert_eq(result.exit_code(), 1)
  assert_true(result.findings[0].witness is Some(String("draft")))
  assert_true(
    @diff.render_compatibility_json(result).contains("request-schema-narrowed"),
  )
}

///|
test "offline validation returns a portable report" {
  let text = "{\"openapi\":\"3.1.1\",\"info\":{\"title\":\"Orders\",\"version\":\"1\"},\"paths\":{}}"
  let result = @validation.validate(text, format=@openapi.Json)
  assert_eq(result.exit_code(), 0)
  assert_true(@validation.render_json(result).contains("\"validation\""))
  assert_true(@diff.render_validation_sarif(result).contains("2.1.0"))
}
