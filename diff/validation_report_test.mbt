///|
test "validation SARIF distinguishes invalid document results from execution failure" {
  let report = @validation.validate(
    "{\"openapi\":\"3.1.1\",\"paths\":{}}",
    format=@openapi.Json,
    source="file:///checkout/api.json",
  )
  assert_eq(report.exit_code(), 1)
  let root = @diff.SarifSourceRoot::new("file:///checkout")
  let rendered = @json.parse(
    @diff.render_validation_sarif(report, source_root=Some(root)),
  )
  match rendered {
    {
      "runs": [
        {
          "invocations": [{ "executionSuccessful": True, .. }],
          "results": [first, ..],
          ..
        },
      ],
      ..
    } => {
      assert_true(first.stringify().contains("api.json"))
      assert_true(first.stringify().contains("validation/v1"))
    }
    _ => fail("expected validation findings from a completed invocation")
  }
}

///|
test "validation SARIF fingerprints distinguish equal pointers in different target files" {
  let report = @validation.validate(
    "{\"openapi\":\"3.1.1\",\"info\":{\"title\":\"Targets\",\"version\":\"1\"},\"paths\":{},\"components\":{\"schemas\":{\"A\":{\"$ref\":\"a.json\"},\"B\":{\"$ref\":\"b.json\"}}}}",
    format=@openapi.Json,
    source="file:///checkout/api.json",
    load=Some((_, path) => {
      text: "{\"type\":9}",
      format: @openapi.Json,
      source: "file:///checkout/" + path,
    }),
  )
  assert_eq(report.exit_code(), 1)
  let root = @diff.SarifSourceRoot::new("file:///checkout/")
  match
    @json.parse(@diff.render_validation_sarif(report, source_root=Some(root))) {
    { "runs": [{ "results": [Object(a), Object(b)], .. }], .. } => {
      assert_true(a["partialFingerprints"] != b["partialFingerprints"])
      assert_true(Json::object(a).stringify().contains("a.json"))
      assert_true(Json::object(b).stringify().contains("b.json"))
    }
    _ => fail("expected two distinct target findings")
  }
}
