///|
fn without(fields : Map[String, Value], names : Array[String]) -> Value {
  let result = Map([])
  for (key, value) in fields {
    if !names.contains(key) {
      result[key] = value
    }
  }
  Obj(result)
}

///|
fn parameter_key(name : String, position : String) -> (String, String) {
  (position, if position == "header" { name.to_lower() } else { name })
}

///|
priv struct ParameterBudget {
  mut count : Int32
  mut nodes : Int32
}

///|
fn charge_contract(
  value : Value,
  at : Location,
  budget : ParameterBudget,
) -> Unit raise AuthError {
  budget.nodes += 1
  if budget.nodes > 1000000 {
    issue(
      "resource.contract-nodes", "Contract extraction exceeds 1000000 expanded nodes",
      at,
    )
  }
  match value {
    Obj(fields) =>
      for (_, child) in fields {
        charge_contract(child, at, budget)
      }
    Seq(items) =>
      for child in items {
        charge_contract(child, at, budget)
      }
    _ => ()
  }
}

///|
fn unevaluated_ref(value : Value) -> Bool {
  match value {
    Obj(fields) =>
      fields.contains("$ref") || fields.values().any(unevaluated_ref)
    Seq(items) => items.any(unevaluated_ref)
    _ => false
  }
}

///|
fn parameters(
  graph : Graph,
  value : Value?,
  location : Location,
  budget : ParameterBudget,
) -> Array[ParameterContract] raise AuthError {
  let values = match value {
    None => return []
    Some(Seq(values)) => values
    Some(_) => {
      issue("contract.parameters", "Expected a parameter array", location)
      abort("unreachable")
    }
  }
  let result = []
  let seen : Map[(String, String), Bool] = Map([])
  for index, value in values {
    budget.count += 1
    if budget.count > 250000 {
      issue(
        "resource.parameters", "Extraction exceeds 250000 parameters", location,
      )
    }
    let (fields, at, _) = graph.resolve(value, location.key(index.to_string()))
    let name = required_string(fields, "name", at)
    let position = required_string(fields, "in", at)
    if !["query", "header", "path", "cookie"].contains(position) {
      issue(
        "contract.parameter-in",
        "Expected query, header, path or cookie",
        at.key("in"),
      )
    }
    let required = match fields.get("required") {
      None => false
      Some(Bool(value)) => value
      Some(_) => {
        issue(
          "contract.parameter-required",
          "required must be a boolean",
          at.key("required"),
        )
        abort("unreachable")
      }
    }
    if position == "path" && !required {
      issue(
        "contract.path-required", "Path parameters must declare required: true",
        at,
      )
    }
    let key = parameter_key(name, position)
    if seen.contains(key) {
      issue("contract.parameter-duplicate", "Duplicate parameter: " + name, at)
    }
    seen[key] = true
    if position == "header" &&
      ["accept", "content-type", "authorization"].contains(name.to_lower()) {
      continue
    }
    let shape = without(fields, [
      "name", "in", "required", "description", "example", "examples", "schema",
    ])
    charge_contract(shape, at, budget)
    if unevaluated_ref(shape) {
      issue(
        "contract.unevaluated-ref", "Schema/content references are not resolved by the parameter profile",
        at,
      )
    }
    result.push({
      name,
      position,
      required,
      definition: value_json(Obj(fields)),
      location: at,
      schema: extract_schema(
        graph,
        fields.get("schema"),
        at.key("schema"),
        budget,
      ),
      shape: canonical(shape),
    })
  }
  result
}

///|
fn contract_operation(
  graph : Graph,
  value : Value,
  inherited : Array[ParameterContract],
  path : String,
  http_method : String,
  at : Location,
  budget : ParameterBudget,
  path_context : String,
) -> OperationContract raise AuthError {
  let fields = object(value, at)
  if fields.contains("$ref") {
    issue(
      "contract.operation-ref",
      "Operation Object cannot be a reference",
      at.key("$ref"),
    )
  }
  let declared = parameters(
    graph,
    fields.get("parameters"),
    at.key("parameters"),
    budget,
  )
  let effective : Map[(String, String), ParameterContract] = Map([])
  for parameter in inherited {
    effective[parameter_key(parameter.name, parameter.position)] = parameter
  }
  for parameter in declared {
    effective[parameter_key(parameter.name, parameter.position)] = parameter
  }
  // Charge inherited copies as well as declarations before they can expand.
  budget.count += inherited.length()
  if budget.count > 250000 {
    issue("resource.parameters", "Extraction exceeds 250000 parameters", at)
  }
  let selected = effective.values().collect()
  selected.sort_by((a, b) => {
    parameter_key(a.name, a.position).compare(parameter_key(b.name, b.position))
  })
  for parameter in selected {
    if parameter.position == "path" &&
      !path.contains("{" + parameter.name + "}") {
      issue(
        "contract.path-parameter",
        "Path parameter is absent from its template",
        parameter.location,
      )
    }
  }
  let remainder = without(fields, [
    "parameters", "operationId", "summary", "description", "tags", "externalDocs",
    "requestBody", "responses",
  ])
  charge_contract(remainder, at, budget)
  if unevaluated_ref(remainder) {
    issue(
      "contract.unevaluated-ref", "References outside parameter declarations are not resolved by this profile",
      at,
    )
  }
  let mut start = 0
  for index in 0..<path.length() {
    if path[index] == '{' {
      start = index + 1
    } else if path[index] == '}' {
      let name = path[start:index].to_owned()
      if !selected.any(p => p.position == "path" && p.name == name) {
        issue(
          "contract.path-parameter",
          "Path template has no required parameter: " + name,
          at,
        )
      }
    }
  }
  {
    http_method,
    path,
    parameters: selected,
    request_body: request_body(
      graph,
      fields.get("requestBody"),
      at.key("requestBody"),
      budget,
    ),
    responses: response_contracts(
      graph,
      fields.get("responses"),
      at.key("responses"),
      budget,
    ),
    location: at,
    complete: true,
    remainder: quote(path_context) + canonical(remainder),
  }
}
