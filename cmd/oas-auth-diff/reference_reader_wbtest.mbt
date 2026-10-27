///|
test "canonical local loader reads a sibling with source identity" {
  let root = canonical_root("cases")
  let from = canonical_source_uri("cases/orders.before.yaml")
  let loaded = load_local_reference(root, from, "orders.after.json")
  assert_eq(loaded.format, @openapi.Json)
  assert_eq(loaded.source, canonical_source_uri("cases/orders.after.json"))
  assert_true(loaded.text.contains("orders:read"))
  assert_eq(
    load_local_reference(root, from, "./orders.after.json").source,
    loaded.source,
  )
}

///|
test "local loader rejects escaping and nonlocal references" {
  let root = canonical_root("cases")
  let from = canonical_source_uri("cases/orders.before.yaml")
  for
    relative in [
      "../moon.mod", "/absolute.yaml", "//host/data.yaml", "C:/drive.yaml", "https://host/data.yaml",
      "dir\\data.yaml", "data.yaml?query", "data\u0000.yaml",
    ] {
    try load_local_reference(root, from, relative) catch {
      @openapi.DocumentError(_) => ()
    } noraise {
      _ => fail("expected confined loader to reject " + relative)
    }
  }
}

///|
test "file URI decoding rejects network malformed and NUL sources" {
  for
    source in [
      "https://host/data.yaml", "file://host/data.yaml", "file:////host/data.yaml",
      "file:///data%00.yaml", "file:///data%GG.yaml", "file:///data.yaml?query",
    ] {
    try source_path(source) catch {
      _ => ()
    } noraise {
      _ => fail("expected invalid local file URI rejection")
    }
  }
}
