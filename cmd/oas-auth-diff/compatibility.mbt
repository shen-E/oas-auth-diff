///|
fn write_compatibility_report(
  comparison : @compat.Comparison,
  format : String,
  source_root~ : @diff.SarifSourceRoot? = None,
) -> Unit {
  println(
    match format {
      "json" => @diff.render_compatibility_json(comparison)
      "sarif" => @diff.render_compatibility_sarif(comparison, source_root~)
      _ => @diff.render_compatibility_text(comparison)
    },
  )
  for diagnostic in comparison.diagnostics {
    stderr(
      "\{diagnostic.location.uri}#\{diagnostic.location.pointer}: \{diagnostic.code}: \{diagnostic.message}",
    )
  }
}
