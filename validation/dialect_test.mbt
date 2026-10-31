///|
test "standard 2020-12 and explicitly supplied dialects validate Schema syntax" {
  let dialect : Json = {
    "$id": "https://example.test/dialect",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$ref": "https://json-schema.org/draft/2020-12/schema",
    "properties": { "x-sensitivity": { "enum": ["public", "private"] } },
  }
  let resources = Map([("https://example.test/dialect", dialect)])
  for
    uri in [
      "https://json-schema.org/draft/2020-12/schema", "https://example.test/dialect",
    ] {
    let document : Json = {
      "openapi": "3.1.1",
      "info": { "title": "Dialect", "version": "1" },
      "paths": {},
      "jsonSchemaDialect": uri,
      "components": {
        "schemas": {
          "Item": {
            "type": "integer",
            "minimum": 1,
            "x-sensitivity": "private",
          },
        },
      },
    }
    let report = @validation.validate(
      document.stringify(),
      format=@openapi.Json,
      dialects=resources,
    )
    if report.exit_code() != 0 {
      fail(@validation.render_text(report))
    }
  }
  let invalid : Json = {
    "openapi": "3.1.1",
    "info": { "title": "Dialect", "version": "1" },
    "paths": {},
    "components": {
      "schemas": {
        "Item": {
          "$schema": "https://example.test/dialect",
          "x-sensitivity": "secret",
        },
      },
    },
  }
  let report = @validation.validate(
    invalid.stringify(),
    format=@openapi.Json,
    dialects=resources,
  )
  assert_eq(report.exit_code(), 1)
  assert_true(
    report.violations.any(v => {
      v.location.pointer == "/components/schemas/Item/x-sensitivity"
    }),
  )
}

///|
test "referenced OpenAPI resources use the target document's declared dialect" {
  let source = "{\"openapi\":\"3.1.1\",\"info\":{\"title\":\"Entry\",\"version\":\"1\"},\"paths\":{},\"components\":{\"schemas\":{\"Data\":{\"$ref\":\"other.json#/components/schemas/Data\"}}}}"
  let dialect : Json = {
    "$id": "https://example.test/dialect",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$ref": "https://json-schema.org/draft/2020-12/schema",
    "properties": { "x-level": { "type": "integer" } },
  }
  let report = @validation.validate(
    source,
    format=@openapi.Json,
    source="file:///entry.json",
    dialects=Map([("https://example.test/dialect", dialect)]),
    load=Some((_, _) => {
      source: "file:///other.json",
      format: @openapi.Json,
      text: "{\"openapi\":\"3.1.1\",\"jsonSchemaDialect\":\"https://example.test/dialect\",\"components\":{\"schemas\":{\"Data\":{\"x-level\":\"wrong\"}}}}",
    }),
  )
  assert_eq(report.exit_code(), 1)
  assert_true(
    report.violations.any(v => {
      v.location.uri == "file:///other.json" &&
      v.location.pointer.has_suffix("/x-level")
    }),
  )
}

///|
test "required unknown vocabularies and malformed dialect definitions stay incomplete" {
  let cases : Array[Json] = [
    {
      "$id": "https://example.test/dialect",
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$vocabulary": { "https://example.test/vocab": true },
    },
    {
      "$id": "https://example.test/dialect",
      "$schema": "https://example.test/dialect",
    },
    {
      "$id": "https://example.test/other",
      "$schema": "https://json-schema.org/draft/2020-12/schema",
    },
    {
      "$id": "https://example.test/dialect",
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "type": 42,
    },
    {
      "$id": "https://example.test/dialect",
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$ref": "#",
    },
  ]
  for dialect in cases {
    let document : Json = {
      "openapi": "3.1.1",
      "info": { "title": "Dialect", "version": "1" },
      "paths": {},
      "jsonSchemaDialect": "https://example.test/dialect",
    }
    assert_eq(
      @validation.validate(
        document.stringify(),
        format=@openapi.Json,
        dialects=Map([("https://example.test/dialect", dialect)]),
      ).exit_code(),
      2,
    )
  }
}
