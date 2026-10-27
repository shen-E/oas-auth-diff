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
  { changes: [], diagnostics, complete: false, }
}

///|
fn operation_key(operation : @openapi.Operation) -> String {
  "\{operation.path}\n\{operation.http_method}"
}

///|
fn scheme_named(
  document : @openapi.Document,
  name : String,
) -> @openapi.Scheme? {
  for scheme in document.schemes {
    if scheme.name == name {
      return Some(scheme)
    }
  }
  None
}

///|
fn scheme_issues(
  before : @openapi.Document,
  after : @openapi.Document,
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
      (scheme_named(before, name), scheme_named(after, name)) {
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
/// Compare operations by exact method and path, preserving partial findings.
pub fn compare(
  before : @openapi.Document,
  after : @openapi.Document,
) -> Comparison {
  let changes : Array[OperationChange] = []
  let diagnostics = before.diagnostics.copy()
  for diagnostic in after.diagnostics {
    diagnostics.push(diagnostic)
  }
  let old_operations : Map[String, @openapi.Operation] = Map([])
  let new_operations : Map[String, @openapi.Operation] = Map([])
  let keys : Array[String] = []
  for operation in before.operations {
    let key = operation_key(operation)
    if operation.policy is None {
      diagnostics.push(@openapi.Diagnostic::{
        code: "operation-incomplete",
        message: "the baseline operation has no resolved authentication policy",
        location: operation.security_location,
      })
    }
    if old_operations.contains(key) {
      diagnostics.push(@openapi.Diagnostic::{
        code: "operation-duplicate",
        message: "the baseline contains duplicate method and path declarations",
        location: operation.location,
      })
    } else {
      keys.push(key)
    }
    old_operations[key] = operation
  }
  for operation in after.operations {
    let key = operation_key(operation)
    if operation.policy is None {
      diagnostics.push(@openapi.Diagnostic::{
        code: "operation-incomplete",
        message: "the candidate operation has no resolved authentication policy",
        location: operation.security_location,
      })
    }
    if new_operations.contains(key) {
      diagnostics.push(@openapi.Diagnostic::{
        code: "operation-duplicate",
        message: "the candidate contains duplicate method and path declarations",
        location: operation.location,
      })
    } else if !old_operations.contains(key) {
      keys.push(key)
    }
    new_operations[key] = operation
  }
  keys.sort()
  for key in keys {
    match (old_operations.get(key), new_operations.get(key)) {
      (Some(old), Some(new)) => {
        let issues = scheme_issues(before, after, old, new)
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
    complete: diagnostics.is_empty() &&
    changes.all(fn(change) { change.kind != Incomparable }),
    diagnostics,
  }
}
