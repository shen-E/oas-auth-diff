///|
test "structural diff retains metadata, extensions, exact numbers and pointer escaping" {
  let before = @openapi.parse_snapshot(
    "{\"openapi\":\"3.1.1\",\"info\":{\"title\":\"Old\"},\"x/a~\":[9007199254740993,1e0]}",
    format=@openapi.Json,
  )
  let after = @openapi.parse_snapshot(
    "openapi: 3.1.1\ninfo: {title: New}\nx/a~: [9007199254740992, 1.00]\nx-added: null\n",
    format=@openapi.Yaml,
  )
  let result = @diff.compare_snapshots(before, after)
  assert_eq(result.changes.length(), 3)
  assert_eq(result.changes[0].pointer, "/info/title")
  assert_eq(result.changes[1].pointer, "/x-added")
  assert_eq(result.changes[1].kind, "added")
  assert_eq(result.changes[2].pointer, "/x~1a~0/0")
  assert_true(@diff.render_structural_json(result).contains("9007199254740993"))
  assert_true(
    @diff.render_structural_json(result, summary=true).contains("\"total\": 3"),
  )
  assert_false(
    @diff.render_structural_json(result, summary=true).contains("\"changes\""),
  )
}

///|
test "structural diff operates on entry values without pretending to resolve references" {
  let a = @openapi.parse_snapshot(
    "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-ref\":{\"$ref\":\"external.yaml\"}}",
    format=@openapi.Json,
  )
  assert_true(a.changes(a).is_empty())
  assert_true(
    @diff.render_structural_text(@diff.compare_snapshots(a, a)).contains(
      "references are not expanded",
    ),
  )
}
