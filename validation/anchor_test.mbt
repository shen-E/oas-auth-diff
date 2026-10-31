///|
fn anchored_document(target : Json) -> Json {
  {
    "openapi": "3.1.1",
    "info": { "title": "Identifiers", "version": "1" },
    "paths": {},
    "components": { "schemas": { "Use": { "$ref": "#Id" }, "Target": target } },
  }
}

///|
test "validation checks named anchor targets and recursive static schemas" {
  let valid = anchored_document({
    "$anchor": "Id",
    "type": "object",
    "properties": { "next": { "$ref": "#Id" } },
  })
  let checked = @validation.validate(valid.stringify(), format=@openapi.Json)
  if checked.exit_code() != 0 {
    fail(@validation.render_text(checked))
  }
  let invalid = @validation.validate(
    anchored_document({ "$anchor": "Id", "type": 7 }).stringify(),
    format=@openapi.Json,
    source="file:///anchors.json",
  )
  assert_eq(invalid.exit_code(), 1)
  assert_true(
    invalid.violations.any(v => {
      v.location.uri == "file:///anchors.json" &&
      v.location.pointer == "/components/schemas/Target/type"
    }),
  )
}

///|
test "unresolved ambiguous and scoped anchors make validation incomplete" {
  for
    target in [
      ({ "type": "string" } : Json),
      { "$id": "https://example.test/schema", "$anchor": "Id" },
      { "$anchor": "Id", "$defs": { "Again": { "$anchor": "Id" } } },
    ] {
    let report = @validation.validate(
      anchored_document(target).stringify(),
      format=@openapi.Json,
    )
    assert_eq(report.exit_code(), 2)
    assert_false(report.complete)
    assert_false(report.diagnostics.is_empty())
  }
}
