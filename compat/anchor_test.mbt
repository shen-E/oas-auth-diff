///|
fn anchor_spec(
  pattern : String,
  reference~ : String = "#Id",
) -> @openapi.Specification raise {
  let value : Json = {
    "openapi": "3.1.1",
    "paths": {
      "/orders": {
        "post": {
          "requestBody": {
            "content": {
              "application/json": { "schema": { "$ref": reference } },
            },
          },
        },
      },
    },
    "components": {
      "schemas": {
        "Identifier": { "$anchor": "Id", "type": "string", "pattern": pattern },
      },
    },
  }
  @openapi.parse_specification(value.stringify(), format=@openapi.Json)
}

///|
test "anchored Schema comparison retains Unicode witnesses and actual target origins" {
  let before = anchor_spec("^[一-龥]+$")
  let after = anchor_spec("^猫+$")
  let report = @compat.compare(before, after)
  assert_eq(report.exit_code(), 1)
  assert_eq(report.findings.length(), 1)
  assert_true(report.findings[0].witness is Some(String(_)))
  assert_eq(@compat.compare(after, before).exit_code(), 0)
  assert_eq(
    @compat.compare(
      after,
      anchor_spec("^猫+$", reference="#/components/schemas/Identifier"),
    ).exit_code(),
    0,
  )
  assert_eq(
    @compat.compare(before, anchor_spec("^猫+$", reference="#Missing")).exit_code(),
    2,
  )
}
