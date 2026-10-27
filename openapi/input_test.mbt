///|
fn reject(
  text : String,
  format : @openapi.InputFormat,
  fragment : String,
) -> Unit raise {
  try @openapi.parse_document(text, format~) catch {
    error => assert_true(error.to_string().contains(fragment))
  } noraise {
    _ => fail("expected malformed input to fail")
  }
}

///|
test "reject duplicate decoded JSON and YAML keys" {
  reject(
    "{\"openapi\":\"3.1.1\",\"open\\u0061pi\":\"3.1.1\",\"paths\":{}}",
    @openapi.Json,
    "Duplicate",
  )
  reject(
    "openapi: 3.1.1\n\"openapi\": 3.1.1\npaths: {}\n",
    @openapi.Yaml,
    "Duplicate YAML key",
  )
  reject(
    "openapi: 3.1.1\npaths: {}\n1: value\n",
    @openapi.Yaml,
    "key must be a string",
  )
}

///|
test "reject YAML documents, tags, anchors, aliases, merge and nonfinite values" {
  reject(
    "---\nopenapi: 3.1.1\npaths: {}\n---\n{}\n",
    @openapi.Yaml,
    "exactly one",
  )
  reject("openapi: !!str 3.1.1\npaths: {}\n", @openapi.Yaml, "tag")
  reject("openapi: 3.1.1\npaths: &p {}\n", @openapi.Yaml, "anchor")
  reject("openapi: 3.1.1\npaths: *p\n", @openapi.Yaml, "alias")
  reject("openapi: 3.1.1\npaths: {}\n<<: {}\n", @openapi.Yaml, "merge")
  reject(
    "openapi: 3.1.1\npaths: {}\nx-example: .inf\n",
    @openapi.Yaml,
    "non-finite",
  )
  reject(
    "%YAML 1.1\n---\nopenapi: 3.1.1\npaths: {}\n",
    @openapi.Yaml,
    "YAML 1.2",
  )
  reject(
    "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-example\":1e999}",
    @openapi.Json,
    "Non-finite",
  )
  let quoted = @openapi.parse_document(
    "openapi: 3.1.1\npaths: {}\nx-example:\n  \"<<\": value\n",
    format=@openapi.Yaml,
  )
  assert_eq(quoted.diagnostics.length(), 0)
}

///|
test "root and unsupported versions are fatal" {
  reject("[]", @openapi.Json, "root must be an object")
  for version in ["2.0", "3.2.0", "3.0.nope", "3.1", "3.1.1.extra"] {
    reject(
      "{\"openapi\":\"" + version + "\",\"paths\":{}}",
      @openapi.Json,
      "Supported OpenAPI",
    )
  }
  reject("{\"openapi\":3.1,\"paths\":{}}", @openapi.Json, "version string")
  reject("{\"openapi\":\"3.1.1\",}", @openapi.Json, "line")
}

///|
test "depth, node, byte and authentication alternative budgets are enforced" {
  let deep = String::make(130, '[') + "0" + String::make(130, ']')
  reject(deep, @openapi.Json, "nesting")
  reject(deep, @openapi.Yaml, "deep")
  let large = "{\"openapi\":\"3.1.1\",\"paths\":{},\"x-value\":\"" +
    String::make(16 * 1024 * 1024, 'a') +
    "\"}"
  reject(large, @openapi.Json, "16 MiB")
  let values = Array::make(250001, "null").join(",")
  reject("[" + values + "]", @openapi.Json, "250000 nodes")
  let requirements = Array::make(257, "{}").join(",")
  let document = @openapi.parse_document(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/pets\":{\"get\":{\"security\":[" +
    requirements +
    "]}}}}",
    format=@openapi.Json,
  )
  assert_eq(document.diagnostics[0].code, "auth.limit")
  assert_true(document.operations[0].policy is None)
}

///|
test "per-clause and total auth atom limits preserve input completeness errors" {
  let names = Array::make(1024, "\"admin\"").join(",")
  let prefix = "{\"openapi\":\"3.1.1\",\"components\":{\"securitySchemes\":{\"Key\":{\"type\":\"http\",\"scheme\":\"bearer\"}}},\"paths\":{\"/pets\":{\"get\":{\"security\":["
  let suffix = "]}}}}"
  let clause = @openapi.parse_document(
    prefix + "{\"Key\":[" + names + "]}" + suffix,
    format=@openapi.Json,
  )
  assert_eq(clause.diagnostics[0].code, "auth.limit")
  assert_true(clause.operations[0].policy is None)
  let names = Array::make(1023, "\"admin\"").join(",")
  let requirements = Array::make(9, "{\"Key\":[" + names + "]}").join(",")
  let total = @openapi.parse_document(
    prefix + requirements + suffix,
    format=@openapi.Json,
  )
  assert_eq(total.diagnostics[0].code, "auth.limit")
  assert_true(total.operations[0].policy is None)
}
