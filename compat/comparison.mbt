///|
/// A confirmed client compatibility break within the endpoint/parameter profile.
pub(all) struct Finding {
  rule_id : String
  http_method : String
  path : String
  parameter : String?
  position : String?
  message : String
  location : @openapi.Location
} derive(Debug, ToJson)

///|
pub extend Finding with Debug::{to_repr}

///|
pub extend Finding with ToJson::{to_json}

///|
pub(all) struct Comparison {
  findings : Array[Finding]
  diagnostics : Array[@openapi.Diagnostic]
  complete : Bool
  before_source : String
  after_source : String
}

///|
/// Incomplete analysis has priority over confirmed breaking findings.
pub fn Comparison::exit_code(self : Comparison) -> Int32 {
  if !self.complete {
    2
  } else if self.findings.is_empty() {
    0
  } else {
    1
  }
}

///|
/// The complete list of checks implemented by this compatibility profile.
pub fn checks() -> Array[String] {
  [
    "endpoint-removed", "request-parameter-added-required", "request-parameter-became-required",
  ]
}

///|
fn unsupported(
  diagnostics : Array[@openapi.Diagnostic],
  message : String,
  at : @openapi.Location,
) -> Unit {
  diagnostics.push({ code: "compat.unclassified", message, location: at, })
}

///|
fn parameter_identity(
  parameter : @openapi.ParameterContract,
) -> (String, String) {
  (
    parameter.position,
    if parameter.position == "header" {
      parameter.name.to_lower()
    } else {
      parameter.name
    },
  )
}

///|
fn has_parameter_default(parameter : @openapi.ParameterContract) -> Bool {
  match parameter.definition {
    Object(fields) =>
      match fields.get("schema") {
        Some(Object(schema)) => schema.contains("default")
        _ => false
      }
    _ => false
  }
}

///|
fn operation_index(
  specification : @openapi.Specification,
  diagnostics : Array[@openapi.Diagnostic],
) -> (
  Map[(String, String), @openapi.OperationContract],
  Map[(String, String), Bool],
) {
  let indexed = Map([])
  let blocked = Map([])
  for operation in specification.operations {
    if @openapi.path_identity(operation.path) is Some(path) {
      let key = (operation.http_method, path)
      if indexed.contains(key) {
        blocked[key] = true
        diagnostics.push({
          code: "compat.operation-duplicate",
          message: "Duplicate operation identity",
          location: operation.location,
        })
      }
      indexed[key] = operation
    } else {
      diagnostics.push({
        code: "compat.path",
        message: "Invalid operation path",
        location: operation.location,
      })
    }
  }
  (indexed, blocked)
}

///|
fn compare_parameters(
  before : @openapi.OperationContract,
  after : @openapi.OperationContract,
  findings : Array[Finding],
  diagnostics : Array[@openapi.Diagnostic],
) -> Unit {
  let previous = Map([])
  let current = Map([])
  for parameter in before.parameters {
    previous[parameter_identity(parameter)] = parameter
  }
  for parameter in after.parameters {
    current[parameter_identity(parameter)] = parameter
    // Template-position matching owns path parameter identity, not its label.
    if parameter.position == "path" {
      continue
    }
    let key = parameter_identity(parameter)
    let rule = match previous.get(key) {
      None if parameter.required => Some("request-parameter-added-required")
      Some(old) if !old.required && parameter.required =>
        Some("request-parameter-became-required")
      _ => None
    }
    if rule is Some(rule_id) {
      findings.push({
        rule_id,
        http_method: after.http_method,
        path: after.path,
        parameter: Some(parameter.name),
        position: Some(parameter.position),
        message: "Previously valid requests can omit " +
        parameter.position +
        " parameter " +
        parameter.name +
        "; the candidate requires it",
        location: parameter.location,
      })
    }
    if previous.get(key) is Some(old) {
      if !old.same_shape(parameter) {
        unsupported(
          diagnostics,
          "Changed parameter schema, serialization or other unevaluated field: " +
          parameter.name,
          parameter.location,
        )
      }
    } else if !parameter.required && has_parameter_default(parameter) {
      unsupported(
        diagnostics,
        "An added optional parameter declares a default; its effect is not classified",
        parameter.location,
      )
    }
  }
  let old_path = before.parameters.filter(p => p.position == "path")
  let new_path = after.parameters.filter(p => p.position == "path")
  // Declaration order need not follow path-template order.
  for parameter in old_path {
    let before_token = "{" + parameter.name + "}"
    let ordinal = before.path.split(before_token).to_array()
    let prefix = ordinal[0].to_owned()
    let prefix_shape = @openapi.path_identity(prefix + "{__parameter__}")
    let mut matched = None
    for candidate in new_path {
      let token = "{" + candidate.name + "}"
      let candidate_prefix = after.path.split(token).to_array()[0].to_owned()
      if @openapi.path_identity(candidate_prefix + "{__parameter__}") ==
        prefix_shape {
        matched = Some(candidate)
        break
      }
    }
    match matched {
      Some(candidate) if parameter.same_shape(candidate) => ()
      _ =>
        unsupported(
          diagnostics,
          "Changed path parameter contract",
          parameter.location,
        )
    }
  }
  if old_path.length() != new_path.length() {
    unsupported(
      diagnostics,
      "Changed path parameter declarations",
      after.location,
    )
  }
  for parameter in before.parameters {
    if parameter.position != "path" &&
      !current.contains(parameter_identity(parameter)) {
      unsupported(
        diagnostics,
        "Removed parameter is not classified by this profile: " + parameter.name,
        after.location,
      )
    }
  }
}

///|
/// Check endpoint removal and new required non-path request parameters.
/// Other changed contract fields produce diagnostics rather than a clean pass.
pub fn compare(
  before : @openapi.Specification,
  after : @openapi.Specification,
) -> Comparison {
  let findings = []
  let diagnostics = before.diagnostics.copy()
  diagnostics.append(after.diagnostics)
  let (previous, previous_blocked) = operation_index(before, diagnostics)
  let (current, current_blocked) = operation_index(after, diagnostics)
  if !before.same_remainder(after) {
    unsupported(
      diagnostics,
      "Changed document fields outside the endpoint/parameter profile",
      { uri: after.source, pointer: "", },
    )
  }
  let keys = previous.keys().collect()
  keys.sort()
  let conflicting = diagnostics.any(d => d.code == "ref.conflict")
  for key in keys {
    if previous_blocked.contains(key) ||
      current_blocked.contains(key) ||
      conflicting {
      continue
    }
    let old = previous[key]
    if !old.complete {
      continue
    }
    match current.get(key) {
      None if after.diagnostics.is_empty() =>
        findings.push({
          rule_id: "endpoint-removed",
          http_method: old.http_method,
          path: old.path,
          parameter: None,
          position: None,
          message: "Operation removed from the candidate contract",
          location: old.location,
        })
      Some(next) if next.complete => {
        if !old.same_remainder(next) {
          unsupported(
            diagnostics,
            "Changed operation fields outside the endpoint/parameter profile",
            next.location,
          )
        }
        compare_parameters(old, next, findings, diagnostics)
      }
      _ => ()
    }
  }
  findings.sort_by((a, b) => {
    (
      a.path,
      a.http_method,
      a.rule_id,
      a.position.unwrap_or(""),
      a.parameter.unwrap_or(""),
    ).compare(
      (
        b.path,
        b.http_method,
        b.rule_id,
        b.position.unwrap_or(""),
        b.parameter.unwrap_or(""),
      ),
    )
  })
  {
    findings,
    complete: diagnostics.is_empty(),
    diagnostics,
    before_source: before.source,
    after_source: after.source,
  }
}
