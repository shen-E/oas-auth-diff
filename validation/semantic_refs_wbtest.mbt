///|
test "cross-object visit exhaustion records one bounded diagnostic" {
  let resolver = @openapi.ReferenceResolver::new({
    source: "file:///api.json",
    text: "{}",
    format: @openapi.Json,
  })
  let context : SemanticContext = {
    resolver,
    violations: [],
    diagnostics: [],
    remaining: 1,
  }
  let at : @openapi.Location = { uri: resolver.source, pointer: "", }
  assert_true(context.spend(at))
  assert_false(context.spend(at))
  assert_false(context.spend(at))
  assert_eq(context.diagnostics.length(), 1)
  assert_eq(context.diagnostics[0].code, "resource.validation-semantics")
}
