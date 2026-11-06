///|
fn referenced_paths(version : String, paths : Json, parameter : Json) -> Json {
  {
    "openapi": version,
    "info": { "title": "Referenced paths", "version": "1" },
    "paths": paths,
    "components": { "parameters": { "Id": parameter } },
  }
}

///|
test "duplicate parameter references retain the duplicate declaration location" {
  for version in ["3.0.3", "3.1.1"] {
    let value = referenced_paths(
      version,
      {
        "/orders": {
          "get": {
            "parameters": [
              { "$ref": "#/components/parameters/Id" },
              { "$ref": "#/components/parameters/Id" },
            ],
            "responses": { "200": { "description": "ok" } },
          },
        },
      },
      { "name": "q", "in": "query", "schema": { "type": "string" } },
    )
    let report = @validation.validate(value.stringify(), format=@openapi.Json)
    assert_eq(report.exit_code(), 1)
    assert_true(
      report.violations.any(v => {
        v.keyword == "parameterIdentity" &&
        v.location.pointer == "/paths/~1orders/get/parameters/1"
      }),
    )
  }
}

///|
test "path parameter coverage uses resolved names while operation overrides remain valid" {
  for version in ["3.0.3", "3.1.1"] {
    let paths : Json = {
      "/orders/{id}": {
        "parameters": [{ "$ref": "#/components/parameters/Id" }],
        "get": {
          "parameters": [{ "$ref": "#/components/parameters/Id" }],
          "responses": { "200": { "description": "ok" } },
        },
      },
    }
    for (name, expected) in [("id", 0), ("other", 1)] {
      let report = @validation.validate(
        referenced_paths(version, paths, {
          "name": name,
          "in": "path",
          "required": true,
          "schema": { "type": "integer" },
        }).stringify(),
        format=@openapi.Json,
      )
      assert_eq(report.exit_code(), expected)
      assert_eq(
        report.violations.any(v => v.keyword == "pathParameter"),
        expected == 1,
      )
      assert_false(report.violations.any(v => v.keyword == "parameterIdentity"))
    }
  }
}

///|
test "operation identities and security names are checked through Path Item chains" {
  let value : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Paths", "version": "1" },
    "paths": { "/a": { "$ref": "#/x-alias" }, "/b": { "$ref": "#/x-alias" } },
    "x-alias": { "$ref": "#/x-item" },
    "x-item": {
      "get": {
        "operationId": "list",
        "security": [{ "Missing": [] }],
        "responses": { "200": { "description": "ok" } },
      },
    },
  }
  let report = @validation.validate(
    value.stringify(),
    format=@openapi.Json,
    source="file:///paths.json",
  )
  assert_eq(report.exit_code(), 1)
  assert_true(
    report.violations.any(v => {
      v.keyword == "operationId" &&
      v.location.pointer == "/x-item/get/operationId"
    }),
  )
  assert_true(
    report.violations.any(v => {
      v.keyword == "securityScheme" &&
      v.location.uri == "file:///paths.json" &&
      v.location.pointer == "/x-item/get/security/0/Missing"
    }),
  )
}

///|
test "external Path Item and parameter references preserve their actual origins" {
  let entry = "{\"openapi\":\"3.1.1\",\"info\":{\"title\":\"Paths\",\"version\":\"1\"},\"paths\":{\"/orders/{id}\":{\"$ref\":\"path.json\"}}}"
  for name in ["id", "q"] {
    let load : (String, String) -> @openapi.SourceDocument raise @openapi.DocumentError = (
      _,
      path,
    ) => {
      if path == "path.json" {
        {
          source: "file:///path.json",
          format: @openapi.Json,
          text: "{\"parameters\":[{\"$ref\":\"parameter.json\"}],\"get\":{\"responses\":{\"200\":{\"description\":\"ok\"}}}}",
        }
      } else {
        {
          source: "file:///parameter.json",
          format: @openapi.Json,
          text: "{\"name\":\"" +
          name +
          "\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}",
        }
      }
    }
    let report = @validation.validate(
      entry,
      format=@openapi.Json,
      source="file:///api.json",
      load=Some(load),
    )
    assert_eq(report.exit_code(), if name == "id" { 0 } else { 1 })
    if name == "q" {
      assert_true(
        report.violations.any(v => {
          v.keyword == "pathParameter" &&
          v.location.uri == "file:///path.json" &&
          v.location.pointer == "/get/parameters"
        }),
      )
    }
  }
}

///|
test "unavailable parameter references stay incomplete without guessed path violations" {
  let value = referenced_paths(
    "3.1.1",
    {
      "/orders/{id}": {
        "get": {
          "parameters": [{ "$ref": "missing.json" }],
          "responses": { "200": { "description": "ok" } },
        },
      },
    },
    { "name": "unused", "in": "query" },
  )
  let report = @validation.validate(value.stringify(), format=@openapi.Json)
  assert_eq(report.exit_code(), 2)
  assert_false(report.violations.any(v => v.keyword == "pathParameter"))
}

///|
test "Path Item references with concrete siblings require an explicit merge policy" {
  let value : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Paths", "version": "1" },
    "paths": {
      "/a": {
        "$ref": "#/x-item",
        "summary": "alias",
        "get": { "responses": { "200": { "description": "local" } } },
      },
    },
    "x-item": { "get": { "responses": { "200": { "description": "target" } } } },
  }
  let report = @validation.validate(value.stringify(), format=@openapi.Json)
  assert_eq(report.exit_code(), 2)
  assert_true(
    report.diagnostics.any(d => d.code == "validation.path-item-sibling"),
  )
}
