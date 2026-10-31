///|
fn ref_document(
  version : String,
  kind : String,
  target : Json,
  reference : String,
) -> Json {
  {
    "openapi": version,
    "info": { "title": "References", "version": "1" },
    "paths": {},
    "components": Json::object(
      Map([(kind, Json::object(Map([("Item", { "$ref": reference })])))]),
    ),
    "x-target": target,
  }
}

///|
test "validation follows typed internal targets and reports actual target locations" {
  let cases : Array[(String, Json, Json)] = [
    ("schemas", { "type": "string" }, { "type": 9 }),
    (
      "parameters",
      { "name": "id", "in": "query", "schema": { "type": "integer" } },
      { "description": "not a parameter" },
    ),
    ("headers", { "schema": { "type": "string" } }, { "schema": { "type": 9 } }),
    ("responses", { "description": "ok" }, {}),
    ("requestBodies", { "content": { "application/json": {} } }, {}),
    (
      "securitySchemes",
      { "type": "apiKey", "in": "header", "name": "token" },
      { "type": "unknown" },
    ),
    (
      "links",
      { "operationId": "list" },
      { "operationRef": "#/a", "operationId": "list" },
    ),
  ]
  for version in ["3.0.3", "3.1.1"] {
    for (kind, good, bad) in cases {
      let valid = @validation.validate(
        ref_document(version, kind, good, "#/x-target").stringify(),
        format=@openapi.Json,
      )
      if valid.exit_code() != 0 {
        fail(@validation.render_text(valid))
      }
      let invalid = @validation.validate(
        ref_document(version, kind, bad, "#/x-target").stringify(),
        format=@openapi.Json,
        source="file:///api.json",
      )
      assert_eq(invalid.exit_code(), 1)
      assert_true(
        invalid.violations.any(v => v.location.pointer.has_prefix("/x-target")),
      )
    }
  }
}

///|
test "recursive schemas are valid while unproductive Reference Object cycles fail" {
  let recursive : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Tree", "version": "1" },
    "paths": {},
    "components": {
      "schemas": {
        "Node": {
          "type": "object",
          "properties": { "next": { "$ref": "#/components/schemas/Node" } },
        },
      },
    },
  }
  assert_eq(
    @validation.validate(recursive.stringify(), format=@openapi.Json).exit_code(),
    0,
  )
  let cyclic = ref_document(
    "3.1.1",
    "responses",
    {},
    "#/components/responses/Item",
  )
  assert_eq(
    @validation.validate(cyclic.stringify(), format=@openapi.Json).exit_code(),
    1,
  )
  let missing = @validation.validate(
    ref_document("3.1.1", "schemas", {}, "#/missing").stringify(),
    format=@openapi.Json,
  )
  assert_eq(missing.exit_code(), 2)
  assert_true(missing.diagnostics.any(d => d.code == "ref.missing"))
}

///|
test "mixed local source targets use caller loading, retain origins and ignore data references" {
  let entry = ref_document("3.1.1", "schemas", {}, "types.yaml#/Order")
  let report = @validation.validate(
    entry.stringify(),
    format=@openapi.Json,
    source="file:///api.json",
    load=Some((from, path) => {
      if from != "file:///api.json" || path != "types.yaml" {
        raise @openapi.DocumentError("unexpected load")
      }
      {
        source: "file:///types.yaml",
        format: @openapi.Yaml,
        text: "Order: {type: 9}\n",
      }
    }),
  )
  assert_eq(report.exit_code(), 1)
  assert_true(
    report.violations.any(v => {
      v.location.uri == "file:///types.yaml" &&
      v.location.pointer == "/Order/type"
    }),
  )
  let data : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Data", "version": "1" },
    "paths": {},
    "components": {
      "schemas": {
        "Data": {
          "const": { "$ref": "https://example.test/data" },
          "examples": [{ "$ref": "missing.yaml" }],
        },
      },
      "examples": { "Example": { "value": { "$ref": "missing.yaml" } } },
    },
  }
  assert_eq(
    @validation.validate(data.stringify(), format=@openapi.Json).exit_code(),
    0,
  )
}

///|
test "schema id scopes and dynamic input references are explicit incomplete results" {
  for
    schema in (
      [
        {
          "$id": "https://example.test/resource",
          "properties": { "x": { "$ref": "other.json" } },
        },
        { "$dynamicRef": "#node" },
      ] : Array[Json]) {
    let document : Json = {
      "openapi": "3.1.1",
      "info": { "title": "Scopes", "version": "1" },
      "paths": {},
      "components": { "schemas": { "Node": schema } },
    }
    assert_eq(
      @validation.validate(document.stringify(), format=@openapi.Json).exit_code(),
      2,
    )
  }
}

///|
test "component and webhook names beginning x- retain their reference semantics" {
  let document : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Names", "version": "1" },
    "paths": {},
    "components": { "schemas": { "x-Node": { "$ref": "#/missing" } } },
    "webhooks": { "x-events": { "$ref": "#/missing-hook" } },
  }
  let report = @validation.validate(document.stringify(), format=@openapi.Json)
  assert_eq(report.exit_code(), 2)
  assert_true(
    report.diagnostics.any(d => {
      d.location.pointer == "/components/schemas/x-Node/$ref"
    }),
  )
  assert_true(
    report.diagnostics.any(d => d.location.pointer == "/webhooks/x-events/$ref"),
  )
}
