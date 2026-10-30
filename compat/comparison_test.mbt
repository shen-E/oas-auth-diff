///|
fn spec(
  parameters : String,
  extra~ : String = "",
) -> @openapi.Specification raise {
  @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"get\":{\"parameters\":" +
    parameters +
    extra +
    "}}}}",
    format=@openapi.Json,
  )
}

///|
test "required parameter additions and requiredness increases break old requests" {
  for position in ["query", "header", "cookie"] {
    let required = "[{\"name\":\"tenant\",\"in\":\"" +
      position +
      "\",\"required\":true}]"
    let optional = "[{\"name\":\"tenant\",\"in\":\"" + position + "\"}]"
    let added = @compat.compare(spec("[]"), spec(required))
    assert_eq(added.exit_code(), 1)
    assert_eq(added.findings[0].rule_id, "request-parameter-added-required")
    let changed = @compat.compare(spec(optional), spec(required))
    assert_eq(changed.exit_code(), 1)
    assert_eq(changed.findings[0].rule_id, "request-parameter-became-required")
    assert_eq(@compat.compare(spec(required), spec(optional)).exit_code(), 0)
    assert_eq(@compat.compare(spec("[]"), spec(optional)).exit_code(), 0)
    assert_eq(@compat.compare(spec(required), spec(required)).exit_code(), 0)
  }
}

///|
test "unclassified changes retain confirmed findings and return incomplete" {
  let before = spec(
    "[]",
    extra=",\"responses\":{\"200\":{\"description\":\"ok\"}}",
  )
  let after = spec(
    "[{\"name\":\"tenant\",\"in\":\"query\",\"required\":true}]",
    extra=",\"responses\":{\"201\":{\"description\":\"created\"}}",
  )
  let comparison = @compat.compare(before, after)
  assert_eq(comparison.exit_code(), 2)
  assert_eq(comparison.findings.length(), 1)
  assert_false(comparison.diagnostics.is_empty())
}

///|
test "parameter schemas and removals are not silently classified" {
  assert_eq(
    @compat.compare(
      spec("[{\"name\":\"q\",\"in\":\"query\",\"schema\":{\"minimum\":1}}]"),
      spec("[{\"name\":\"q\",\"in\":\"query\",\"schema\":{\"minimum\":2}}]"),
    ).exit_code(),
    2,
  )
  assert_eq(
    @compat.compare(spec("[{\"name\":\"q\",\"in\":\"query\"}]"), spec("[]")).exit_code(),
    2,
  )
  assert_eq(
    @compat.compare(spec("[]"), spec("[]", extra=",\"security\":[{}]")).exit_code(),
    2,
  )
}

///|
test "header case and ignored reserved headers follow OpenAPI parameter semantics" {
  assert_eq(
    @compat.compare(
      spec("[{\"name\":\"X-ID\",\"in\":\"header\",\"required\":true}]"),
      spec("[{\"name\":\"x-id\",\"in\":\"header\",\"required\":true}]"),
    ).exit_code(),
    0,
  )
  for name in ["Accept", "Content-Type", "Authorization"] {
    assert_eq(
      @compat.compare(
        spec("[]"),
        spec(
          "[{\"name\":\"" + name + "\",\"in\":\"header\",\"required\":true}]",
        ),
      ).exit_code(),
      0,
    )
  }
}

///|
test "referenced parameter components do not hide a requiredness increase" {
  let before = spec("[]")
  let after = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"components\":{\"parameters\":{\"Q\":{\"name\":\"q\",\"in\":\"query\",\"required\":true}}},\"paths\":{\"/orders\":{\"get\":{\"parameters\":[{\"$ref\":\"#/components/parameters/Q\"}]}}}}",
    format=@openapi.Json,
  )
  let report = @compat.compare(before, after)
  assert_eq(report.exit_code(), 1)
  assert_eq(report.findings[0].location.pointer, "/components/parameters/Q")
}

///|
test "path parameter renames preserve operation matching" {
  let before = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders/{id}\":{\"get\":{\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true}]}}}}",
    format=@openapi.Json,
  )
  let after = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders/{order_id}\":{\"get\":{\"parameters\":[{\"name\":\"order_id\",\"in\":\"path\",\"required\":true},{\"name\":\"tenant\",\"in\":\"query\",\"required\":true}]}}}}",
    format=@openapi.Json,
  )
  let report = @compat.compare(before, after)
  assert_eq(report.exit_code(), 1)
  assert_eq(report.findings.length(), 1)
  assert_eq(report.findings[0].rule_id, "request-parameter-added-required")
}

///|
test "removed operations break but invalid candidate paths do not invent removals" {
  let empty = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{}}",
    format=@openapi.Json,
  )
  let removed = @compat.compare(spec("[]"), empty)
  assert_eq(removed.exit_code(), 1)
  assert_eq(removed.findings[0].rule_id, "endpoint-removed")
  let invalid = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":3}}",
    format=@openapi.Json,
  )
  let report = @compat.compare(spec("[]"), invalid)
  assert_eq(report.exit_code(), 2)
  assert_true(report.findings.is_empty())
}

///|
test "parameter defaults are inspected as fields rather than string literals" {
  let literal = spec(
    "[{\"name\":\"q\",\"in\":\"query\",\"schema\":{\"enum\":[\"default\"]}}]",
  )
  assert_eq(@compat.compare(spec("[]"), literal).exit_code(), 0)
  let defaulted = spec(
    "[{\"name\":\"q\",\"in\":\"query\",\"schema\":{\"default\":\"x\"}}]",
  )
  assert_eq(@compat.compare(spec("[]"), defaulted).exit_code(), 2)
}
