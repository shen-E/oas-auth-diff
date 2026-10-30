///|
test "compatibility JSON and SARIF retain the profile and verified findings" {
  let before = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"get\":{}}}}",
    format=@openapi.Json,
    source="file:///checkout/before.json",
  )
  let after = @openapi.parse_specification(
    "{\"openapi\":\"3.1.1\",\"paths\":{\"/orders\":{\"get\":{\"parameters\":[{\"name\":\"tenant\",\"in\":\"query\",\"required\":true}]}}}}",
    format=@openapi.Json,
    source="file:///checkout/after.json",
  )
  let comparison = @compat.compare(before, after)
  let report = @json.parse(@diff.render_compatibility_json(comparison))
  match report {
    {
      "report_kind": String("compatibility"),
      "scope": String("endpoint-removal-and-required-parameters"),
      "exit_code": Number(1, ..),
      "findings": [finding],
      ..
    } => assert_true(finding.stringify().contains("tenant"))
    _ => fail("unexpected compatibility report")
  }
  let root = @diff.SarifSourceRoot::new("file:///checkout/")
  let sarif = @json.parse(
    @diff.render_compatibility_sarif(comparison, source_root=Some(root)),
  )
  match sarif {
    {
      "version": String("2.1.0"),
      "runs": [
        {
          "results": [
            {
              "ruleId": String("request-parameter-added-required"),
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": String("after.json"),
                      "uriBaseId": String("%SRCROOT%"),
                      ..
                    },
                    ..
                  },
                  ..
                },
              ],
              ..
            },
          ],
          ..
        },
      ],
      ..
    } => ()
    _ => fail("unexpected compatibility SARIF")
  }
  assert_true(@diff.render_compatibility_text(comparison).contains("3 checks"))
}
