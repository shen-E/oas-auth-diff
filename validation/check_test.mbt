///|
fn document(version : String) -> Json {
  {
    "openapi": version,
    "info": { "title": "Orders", "version": "1.0.0" },
    "paths": {
      "/orders": { "get": { "responses": { "200": { "description": "ok" } } } },
    },
  }
}

///|
test "official metaschemas accept OpenAPI 3.0 and 3.1 JSON/YAML documents" {
  for version in ["3.0.3", "3.1.1"] {
    let report = @validation.validate(
      document(version).stringify(),
      format=@openapi.Json,
    )
    assert_eq(report.exit_code(), 0)
    assert_true(report.complete)
    assert_true(report.violations.is_empty())
  }
  let report = @validation.validate(
    "openapi: 3.1.1\ninfo: {title: Orders, version: '1.0.0'}\npaths: {}\n",
    format=@openapi.Yaml,
  )
  assert_eq(report.exit_code(), 0)
}

///|
test "missing required fields and malformed schema assertions fail with true pointers" {
  for version in ["3.0.3", "3.1.1"] {
    let missing : Json = { "openapi": version, "paths": {} }
    let report = @validation.validate(
      missing.stringify(),
      format=@openapi.Json,
      source="file:///api.json",
    )
    assert_eq(report.exit_code(), 1)
    assert_true(report.violations.any(v => v.keyword == "required"))
    let bad_schema : Json = {
      "openapi": version,
      "info": { "title": "Orders", "version": "1.0.0" },
      "paths": {
        "/orders": {
          "get": {
            "responses": {
              "200": {
                "description": "ok",
                "content": { "application/json": { "schema": { "type": 9 } } },
              },
            },
          },
        },
      },
    }
    let bad = @validation.validate(bad_schema.stringify(), format=@openapi.Json)
    assert_eq(bad.exit_code(), 1)
    assert_false(bad.violations.is_empty())
  }
}

///|
test "validation covers legal assertions beyond the inclusion solver" {
  let valid : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Orders", "version": "1.0.0" },
    "components": {
      "schemas": {
        "Order": {
          "type": "object",
          "properties": {
            "id": { "type": "integer", "minimum": 1 },
            "name": { "type": "string", "minLength": 1 },
          },
        },
      },
    },
    "paths": {},
  }
  let result = @validation.validate(valid.stringify(), format=@openapi.Json)
  if result.exit_code() != 0 {
    fail(@validation.render_text(result))
  }
  let custom : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Orders", "version": "1.0.0" },
    "jsonSchemaDialect": "https://example.test/custom",
    "paths": {},
  }
  assert_eq(
    @validation.validate(custom.stringify(), format=@openapi.Json).exit_code(),
    2,
  )
}

///|
test "path cross checks catch duplicate operation IDs and undeclared security schemes" {
  let invalid : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Orders", "version": "1.0.0" },
    "security": [{ "Missing": [] }],
    "paths": {
      "/orders/{id}": {
        "get": {
          "operationId": "orders",
          "responses": { "200": { "description": "ok" } },
        },
        "post": {
          "operationId": "orders",
          "responses": { "200": { "description": "ok" } },
        },
      },
    },
  }
  let result = @validation.validate(invalid.stringify(), format=@openapi.Json)
  assert_eq(result.exit_code(), 1)
  assert_true(result.violations.any(v => v.keyword == "operationId"))
  assert_true(result.violations.any(v => v.keyword == "securityScheme"))
  assert_true(result.violations.any(v => v.keyword == "pathParameter"))
}

///|
test "dialect overrides are incomplete while example contents stay ordinary data" {
  let custom : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Orders", "version": "1.0.0" },
    "components": {
      "schemas": {
        "Order": {
          "properties": {
            "x-state": { "$schema": "https://example.test/custom" },
          },
        },
      },
    },
    "paths": {},
  }
  let report = @validation.validate(custom.stringify(), format=@openapi.Json)
  assert_eq(report.exit_code(), 2)
  assert_true(report.diagnostics[0].location.pointer.contains("x-state"))
  let example : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Orders", "version": "1.0.0" },
    "components": {
      "schemas": {
        "Order": { "example": { "$schema": "https://example.test/data" } },
      },
    },
    "paths": {},
  }
  assert_eq(
    @validation.validate(example.stringify(), format=@openapi.Json).exit_code(),
    0,
  )
}

///|
test "large validation failure sets retain a bounded report and incomplete status" {
  let fields = Map([
    ("openapi", Json::string("3.1.1")),
    ("info", { "title": "Orders", "version": "1.0.0" }),
    ("paths", {}),
  ])
  for index in 0..<1100 {
    fields["unknown-" + index.to_string()] = Json::number(0)
  }
  let report = @validation.validate(
    Json::object(fields).stringify(),
    format=@openapi.Json,
  )
  assert_eq(report.exit_code(), 2)
  assert_eq(report.violations.length(), 1000)
  assert_true(
    report.diagnostics.any(d => d.code == "resource.validation-results"),
  )
}
