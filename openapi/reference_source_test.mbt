///|
test "reference resolver snapshots support fragments and a bounded caller loader" {
  let resolver = @openapi.ReferenceResolver::new({
    text: "{\"a/b\":{\"~x\":42}}",
    format: @openapi.Json,
    source: "file:///entry.json",
  })
  match resolver.resolve("#/a~1b/~0x", { uri: resolver.source, pointer: "", }) {
    Ok((value, at)) => {
      assert_eq(value, Json::number(42))
      assert_eq(at.pointer, "/a~1b/~0x")
    }
    Err(_) => fail("expected internal pointer resolution")
  }
  assert_true(
    resolver.resolve("#/missing", { uri: resolver.source, pointer: "", })
    is Err(_),
  )
  assert_true(
    resolver.resolve("https://example.test/api", {
      uri: resolver.source,
      pointer: "",
    })
    is Err(_),
  )
  let split = @openapi.ReferenceResolver::new(
    { text: "{}", format: @openapi.Json, source: "file:///entry.json", },
    load=Some((_, path) => {
      if path != "schema.yaml" {
        raise @openapi.DocumentError("unexpected path")
      }
      {
        text: "type: string\n",
        format: @openapi.Yaml,
        source: "file:///schema.yaml",
      }
    }),
  )
  assert_true(
    split.resolve("schema.yaml#/type", { uri: split.source, pointer: "", })
    is Ok((String("string"), _)),
  )
}
