///|
/// The relation between the permissions accepted by two operation declarations.
pub(all) enum ChangeKind {
  Equivalent
  Strengthened
  Weakened
  Mixed
  Added
  Removed
  Incomparable
} derive(Debug, Eq)

///|
pub extend ChangeKind with Debug::{to_repr}

///|
pub extend ChangeKind with Eq::{equal, not_equal}

///|
pub(all) struct OperationChange {
  http_method : String
  path : String
  before_path : String?
  after_path : String?
  operation_id : String?
  kind : ChangeKind
  before : @logic.Policy?
  after : @logic.Policy?
  witness : @logic.GrantSet?
  location : @openapi.Location
} derive(Debug)

///|
pub extend OperationChange with Debug::{to_repr}

///|
pub(all) struct Comparison {
  changes : Array[OperationChange]
  diagnostics : Array[@openapi.Diagnostic]
  complete : Bool
  before_source : String?
  after_source : String?
  before_document_url : String?
  after_document_url : String?
} derive(Debug)

///|
pub extend Comparison with Debug::{to_repr}

///|
/// Invalid or incomplete analysis takes priority over a discovered regression.
pub fn Comparison::exit_code(self : Comparison) -> Int32 {
  if !self.complete {
    return 2
  }
  if self.changes.any(fn(change) {
      change.kind == Weakened || change.kind == Mixed
    }) {
    1
  } else {
    0
  }
}

///|
/// Construct a structured failure result when a document cannot be loaded.
pub fn failure_report(diagnostics : Array[@openapi.Diagnostic]) -> Comparison {
  {
    changes: [],
    diagnostics,
    complete: false,
    before_source: None,
    after_source: None,
    before_document_url: None,
    after_document_url: None,
  }
}

///|
priv struct OperationIndex {
  operations : Map[(String, String), @openapi.Operation]
  blocked : Map[(String, String), Bool]
  ambiguous_paths : Map[String, Bool]
}

///|
fn operation_order(
  left : @openapi.Operation,
  right : @openapi.Operation,
) -> Int32 {
  for
    (a, b) in [
      (left.path, right.path),
      (left.http_method, right.http_method),
      (left.location.uri, right.location.uri),
      (left.location.pointer, right.location.pointer),
      (left.operation_id.unwrap_or(""), right.operation_id.unwrap_or("")),
    ] {
    let order = a.compare(b)
    if order != 0 {
      return order
    }
  }
  0
}

///|
fn index_operations(
  document : @openapi.Document,
  side : String,
  diagnostics : Array[@openapi.Diagnostic],
) -> OperationIndex {
  let operations : Map[(String, String), @openapi.Operation] = Map([])
  let blocked : Map[(String, String), Bool] = Map([])
  let exact : Map[(String, String), Bool] = Map([])
  let paths : Map[String, Map[String, Bool]] = Map([])
  let ordered = document.operations.copy()
  ordered.sort_by(operation_order)
  for operation in ordered {
    let shape = @openapi.path_identity(operation.path)
    // Tag invalid raw paths so /{} cannot collide with a valid /{name} shape.
    let identity = match shape {
      Some(shape) => "path:" + shape
      None => "invalid:" + operation.path
    }
    let key = (operation.http_method, identity)
    let raw_key = (operation.http_method, operation.path)
    if exact.contains(raw_key) {
      blocked[key] = true
      diagnostics.push(@openapi.Diagnostic::{
        code: "operation-duplicate",
        message: "the \{side} contains duplicate method and path declarations",
        location: operation.location,
      })
    }
    exact[raw_key] = true
    if shape is None {
      blocked[key] = true
      diagnostics.push(@openapi.Diagnostic::{
        code: "auth.path",
        message: "the \{side} operation has an invalid path template: " +
        operation.path,
        location: operation.location,
      })
    } else {
      let raw_paths = match paths.get(identity) {
        Some(raw_paths) => raw_paths
        None => {
          let raw_paths = Map([])
          paths[identity] = raw_paths
          raw_paths
        }
      }
      raw_paths[operation.path] = true
    }
    if operation.policy is None {
      diagnostics.push(@openapi.Diagnostic::{
        code: "operation-incomplete",
        message: "the \{side} operation has no resolved authentication policy",
        location: operation.security_location,
      })
    }
    match operations.get(key) {
      Some(_) => blocked[key] = true
      None => operations[key] = operation
    }
  }
  let ambiguous_paths : Map[String, Bool] = Map([])
  for identity, names in paths {
    if names.length() > 1 {
      ambiguous_paths[identity] = true
    }
  }
  for operation in ordered {
    if @openapi.path_identity(operation.path) is Some(shape) &&
      ambiguous_paths.contains("path:" + shape) {
      diagnostics.push(@openapi.Diagnostic::{
        code: "path-duplicate",
        message: "the \{side} contains different paths with the same template: " +
        operation.path,
        location: operation.location,
      })
    }
  }
  { operations, blocked, ambiguous_paths, }
}

///|
fn blocked_change(
  before : @openapi.Operation?,
  after : @openapi.Operation?,
) -> OperationChange {
  let operation = match after {
    Some(operation) => operation
    None => before.unwrap()
  }
  {
    http_method: operation.http_method,
    path: operation.path,
    before_path: before.map(operation => operation.path),
    after_path: after.map(operation => operation.path),
    operation_id: operation.operation_id,
    kind: Incomparable,
    before: None,
    after: None,
    witness: None,
    location: operation.location,
  }
}

///|
fn scheme_named(
  operation : @openapi.Operation,
  name : String,
) -> @openapi.Scheme? {
  for scheme in operation.scheme_identities {
    if scheme.name == name {
      return Some(scheme)
    }
  }
  None
}

///|
fn scheme_issues(
  old_operation : @openapi.Operation,
  new_operation : @openapi.Operation,
) -> Array[@openapi.Diagnostic] {
  let names = old_operation.schemes.copy()
  for name in new_operation.schemes {
    if !names.contains(name) {
      names.push(name)
    }
  }
  names.sort()
  let issues = []
  for name in names {
    let message = match
      (scheme_named(old_operation, name), scheme_named(new_operation, name)) {
      (Some(old), Some(new)) if old.fingerprint == new.fingerprint => None
      (Some(_), Some(_)) =>
        Some(
          "security scheme '\{name}' changed its authentication configuration",
        )
      _ =>
        Some(
          "security scheme '\{name}' is not declared with the same identity in both documents",
        )
    }
    if message is Some(message) {
      issues.push(@openapi.Diagnostic::{
        code: "scheme-incomparable",
        message,
        location: new_operation.security_location,
      })
    }
  }
  issues
}

///|
/// Compare exact methods and path-template shapes, preserving original paths.
pub fn compare(
  before : @openapi.Document,
  after : @openapi.Document,
) -> Comparison {
  let changes : Array[OperationChange] = []
  let diagnostics = before.diagnostics.copy()
  for diagnostic in after.diagnostics {
    diagnostics.push(diagnostic)
  }
  let old_index = index_operations(before, "baseline", diagnostics)
  let new_index = index_operations(after, "candidate", diagnostics)
  let old_operations = old_index.operations
  let new_operations = new_index.operations
  let keys = old_operations.keys().collect()
  for key in new_operations.keys() {
    if !old_operations.contains(key) {
      keys.push(key)
    }
  }
  keys.sort_by(fn(left, right) {
    let path_order = left.1.compare(right.1)
    if path_order != 0 {
      path_order
    } else {
      left.0.compare(right.0)
    }
  })
  for key in keys {
    if old_index.blocked.contains(key) ||
      new_index.blocked.contains(key) ||
      old_index.ambiguous_paths.contains(key.1) ||
      new_index.ambiguous_paths.contains(key.1) {
      changes.push(
        blocked_change(old_operations.get(key), new_operations.get(key)),
      )
      continue
    }
    match (old_operations.get(key), new_operations.get(key)) {
      (Some(old), Some(new)) => {
        let issues = scheme_issues(old, new)
        for issue in issues {
          diagnostics.push(issue)
        }
        let (kind, witness) = match (old.policy, new.policy) {
          (Some(old_policy), Some(new_policy)) if issues.is_empty() => {
            let new_implies_old = new_policy.implies(old_policy)
            let old_implies_new = old_policy.implies(new_policy)
            let kind = match (new_implies_old, old_implies_new) {
              (true, true) => Equivalent
              (true, false) => Strengthened
              (false, true) => Weakened
              (false, false) => Mixed
            }
            if new_implies_old {
              (kind, None)
            } else {
              match new_policy.witness_against(old_policy) {
                Some(grants) if new_policy.allows(grants) &&
                  !old_policy.allows(grants) => (kind, Some(grants))
                _ => {
                  diagnostics.push(@openapi.Diagnostic::{
                    code: "invalid-witness",
                    message: "the proposed permission witness failed independent evaluation",
                    location: new.security_location,
                  })
                  (Incomparable, None)
                }
              }
            }
          }
          _ => (Incomparable, None)
        }
        changes.push({
          http_method: new.http_method,
          path: new.path,
          before_path: Some(old.path),
          after_path: Some(new.path),
          operation_id: new.operation_id,
          kind,
          before: old.policy,
          after: new.policy,
          witness,
          location: new.security_location,
        })
      }
      (None, Some(new)) =>
        changes.push({
          http_method: new.http_method,
          path: new.path,
          before_path: None,
          after_path: Some(new.path),
          operation_id: new.operation_id,
          kind: Added,
          before: None,
          after: new.policy,
          witness: None,
          location: new.location,
        })
      (Some(old), None) =>
        changes.push({
          http_method: old.http_method,
          path: old.path,
          before_path: Some(old.path),
          after_path: None,
          operation_id: old.operation_id,
          kind: Removed,
          before: old.policy,
          after: None,
          witness: None,
          location: old.location,
        })
      (None, None) => ()
    }
  }
  diagnostics.sort_by(fn(left, right) {
    let a = "\{left.location.uri}\n\{left.location.pointer}\n\{left.code}\n\{left.message}"
    let b = "\{right.location.uri}\n\{right.location.pointer}\n\{right.code}\n\{right.message}"
    a.compare(b)
  })
  {
    changes,
    before_source: Some(before.source),
    after_source: Some(after.source),
    before_document_url: before.document_url,
    after_document_url: after.document_url,
    complete: diagnostics.is_empty() &&
    changes.all(fn(change) { change.kind != Incomparable }),
    diagnostics,
  }
}
