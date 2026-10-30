///|
/// Entry-document values for structural diffing, without reference expansion.
pub struct Snapshot {
  source : String
  version : String
  priv root : Value
}

///|
pub(all) struct ValueChange {
  kind : String
  pointer : String
  before : Json?
  after : Json?
} derive(Debug, ToJson)

///|
pub extend ValueChange with Debug::{to_repr}

///|
pub extend ValueChange with ToJson::{to_json}

///|
/// Strict JSON/YAML loading with the shared input limits. This checks the
/// document version, not the validity of every OpenAPI field.
pub fn parse_snapshot(
  text : String,
  format~ : InputFormat,
  source~ : String = "<input>",
) -> Snapshot raise DocumentError {
  let (root, _) = read_input(text, format)
  let version = match root {
    Obj(fields) =>
      match fields.get("openapi") {
        Some(Str(version)) if minor_version(version) is Some(_) => version
        _ =>
          raise DocumentError(
            "Expected an OpenAPI 3.0.x or 3.1.x version string",
          )
      }
    _ => raise DocumentError("OpenAPI root must be an object")
  }
  { source, version, root, }
}

///|
fn changed_values(
  before : Value?,
  after : Value?,
  pointer : String,
  changes : Array[ValueChange],
) -> Unit {
  match (before, after) {
    (Some(Obj(a)), Some(Obj(b))) => {
      let keys = a.keys().collect()
      for key in b.keys() {
        if !a.contains(key) {
          keys.push(key)
        }
      }
      keys.sort()
      for key in keys {
        changed_values(
          a.get(key),
          b.get(key),
          pointer_key(pointer, key),
          changes,
        )
      }
    }
    (Some(Seq(a)), Some(Seq(b))) => {
      let length = if a.length() > b.length() { a.length() } else { b.length() }
      for index in 0..<length {
        changed_values(
          a.get(index),
          b.get(index),
          pointer_key(pointer, index.to_string()),
          changes,
        )
      }
    }
    (Some(a), Some(b)) if canonical(a) == canonical(b) => ()
    (None, None) => ()
    _ =>
      changes.push({
        kind: if before is None {
          "added"
        } else if after is None {
          "removed"
        } else {
          "modified"
        },
        pointer,
        before: before.map(value_json),
        after: after.map(value_json),
      })
  }
}

///|
/// Enumerate source-value edits in stable pointer order. Array order is
/// significant; this does not classify compatibility or dereference schemas.
pub fn Snapshot::changes(
  self : Snapshot,
  other : Snapshot,
) -> Array[ValueChange] {
  let changes = []
  changed_values(Some(self.root), Some(other.root), "", changes)
  changes.sort_by((a, b) => a.pointer.lexical_compare(b.pointer))
  changes
}
