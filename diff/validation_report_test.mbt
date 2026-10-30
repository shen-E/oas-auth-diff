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
