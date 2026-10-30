///|
pub struct StructuralComparison {
  changes : Array[@openapi.ValueChange]
  before_source : String
  after_source : String
}

///|
/// General entry-document diff, including documentation and extension fields.
pub fn compare_snapshots(
  before : @openapi.Snapshot,
  after : @openapi.Snapshot,
) -> StructuralComparison {
  {
    changes: before.changes(after),
    before_source: before.source,
    after_source: after.source,
  }
}

///|
pub fn render_structural_json(
  comparison : StructuralComparison,
  summary~ : Bool = false,
) -> String {
  let counts : Json = {
    "added": comparison.changes.filter(c => c.kind == "added").length(),
    "removed": comparison.changes.filter(c => c.kind == "removed").length(),
    "modified": comparison.changes.filter(c => c.kind == "modified").length(),
    "total": comparison.changes.length(),
  }
  let report : Map[String, Json] = Map([
    ("schema_version", Json::number(1)),
    (
      "report_kind",
      Json::string(if summary { "summary" } else { "structural-diff" }),
    ),
    ("scope", Json::string("entry-document-values")),
    ("complete", Json::boolean(true)),
    (
      "document_sources",
      { "before": comparison.before_source, "after": comparison.after_source },
    ),
    ("counts", counts),
  ])
  if !summary {
    report["changes"] = Json(comparison.changes)
  }
  Json::object(report).stringify(indent=2)
}

///|
pub fn render_structural_text(
  comparison : StructuralComparison,
  summary~ : Bool = false,
) -> String {
  let lines = [
    "oas-auth-diff: entry-document values (references are not expanded)",
  ]
  if !summary {
    for change in comparison.changes {
      lines.push(
        change.kind +
        " #" +
        change.pointer +
        ": " +
        change.before.map(v => v.stringify()).unwrap_or("<absent>") +
        " -> " +
        change.after.map(v => v.stringify()).unwrap_or("<absent>"),
      )
    }
  }
  lines.push("Changes: " + comparison.changes.length().to_string())
  lines.join("\n")
}
