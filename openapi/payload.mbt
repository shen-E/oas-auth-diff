///|
fn Graph::schema_value(
  self : Graph,
  value : Value,
  at : Location,
  budget : ParameterBudget,
  seen : Map[(String, String), Bool],
  depth : Int32,
) -> (Value, Location) raise AuthError {
  if depth > 128 {
    issue("resource.schema-depth", "Schema expansion exceeds 128 levels", at)
  }
  budget.nodes += 1
  if budget.nodes > 1000000 {
    issue(
      "resource.contract-nodes", "Contract extraction exceeds 1000000 expanded nodes",
      at,
    )
  }
  let fields = match value {
    Bool(_) => return (value, at)
    _ => object(value, at)
  }
  if fields.contains("$id") {
    issue(
      "contract.schema-id",
      "Schema $id resource scopes are not yet resolved",
      at.key("$id"),
    )
  }
  if fields.get("$ref") is Some(reference) {
    for key in fields.keys() {
      if !["$ref", "summary", "description", "title"].contains(key) &&
        !key.has_prefix("x-") {
        issue(
          "ref.sibling",
          "Schema reference siblings require conjunctive analysis: " + key,
          at.key(key),
        )
      }
    }
    let reference = string(reference, at.key("$ref"))
    let (target, origin) = self.lookup_ref(reference, at.key("$ref"))
    let key = (origin.uri, origin.pointer)
    if seen.contains(key) {
      issue(
        "ref.cycle",
        "Recursive Schema reference: " + reference,
        at.key("$ref"),
      )
    }
    let nested = seen.copy()
    nested[key] = true
    return self.schema_value(target, origin, budget, nested, depth + 1)
  }
  let result = fields.copy()
  for (key, child) in fields {
    let location = at.key(key)
    if [
        "properties", "$defs", "definitions", "dependentSchemas", "patternProperties",
      ].contains(key) {
      let entries = object(child, location)
      let mapped = Map([])
      for (name, schema) in entries {
        mapped[name] = self.schema_value(
            schema,
            location.key(name),
            budget,
            seen,
            depth + 1,
          ).0
      }
      result[key] = Obj(mapped)
    } else if [
        "items", "additionalProperties", "not", "contains", "if", "then", "else",
        "propertyNames", "unevaluatedProperties", "unevaluatedItems", "additionalItems",
      ].contains(key) {
      result[key] = self.schema_value(child, location, budget, seen, depth + 1).0
    } else if ["allOf", "anyOf", "oneOf", "prefixItems"].contains(key) {
      match child {
        Seq(items) => {
          let mapped = []
          for index, item in items {
            mapped.push(
              self.schema_value(
                item,
                location.key(index.to_string()),
                budget,
                seen,
                depth + 1,
              ).0,
            )
          }
          result[key] = Seq(mapped)
        }
        _ => issue("contract.schema", "Expected an array of schemas", location)
      }
    } else {
      charge_contract(child, location, budget)
    }
  }
  (Obj(result), at)
}

///|
fn extract_schema(
  graph : Graph,
  value : Value?,
  at : Location,
  budget : ParameterBudget,
) -> SchemaContract? raise AuthError {
  match value {
    None => None
    Some(value) => {
      let seen = Map([((at.uri, at.pointer), true)])
      let (value, location) = graph.schema_value(value, at, budget, seen, 0)
      Some({ definition: value_json(value), location, })
    }
  }
}

///|
fn media_content(
  graph : Graph,
  value : Value?,
  at : Location,
  budget : ParameterBudget,
) -> Array[MediaContract] raise AuthError {
  let fields = match value {
    None => return []
    Some(value) => object(value, at)
  }
  let result = []
  let seen = Map([])
  for media_type in sorted_keys(fields) {
    let location = at.key(media_type)
    if !media_type.contains("/") {
      issue("contract.media-type", "Expected a media type", location)
    }
    let media = object(fields[media_type], location)
    let normalized = if media_type.contains(";") {
      media_type
    } else {
      media_type.to_lower()
    }
    if seen.contains(normalized) {
      issue(
        "contract.media-duplicate", "Duplicate media type ignoring case", location,
      )
    }
    seen[normalized] = true
    let schema = extract_schema(
      graph,
      media.get("schema"),
      location.key("schema"),
      budget,
    )
    let remainder = without(media, ["schema", "example", "examples"])
    charge_contract(remainder, location, budget)
    if unevaluated_ref(remainder) {
      issue(
        "contract.unevaluated-ref", "References outside payload schemas are not yet resolved",
        location,
      )
    }
    result.push({
      media_type: normalized,
      schema,
      location,
      remainder: canonical(remainder),
    })
  }
  result
}

///|
fn request_body(
  graph : Graph,
  value : Value?,
  at : Location,
  budget : ParameterBudget,
) -> BodyContract? raise AuthError {
  let value = match value {
    None => return None
    Some(value) => value
  }
  let (fields, location, _) = graph.resolve(value, at)
  let required = match fields.get("required") {
    None => false
    Some(Bool(value)) => value
    _ => {
      issue(
        "contract.body-required",
        "Request body required must be a boolean",
        location.key("required"),
      )
      abort("unreachable")
    }
  }
  if !fields.contains("content") {
    issue("contract.body-content", "Request body requires content", location)
  }
  let content = media_content(
    graph,
    fields.get("content"),
    location.key("content"),
    budget,
  )
  let remainder = without(fields, ["required", "content", "description"])
  charge_contract(remainder, location, budget)
  if unevaluated_ref(remainder) {
    issue("contract.unevaluated-ref", "Unresolved request body field", location)
  }
  Some({ required, content, location, remainder: canonical(remainder), })
}

///|
fn response_contracts(
  graph : Graph,
  value : Value?,
  at : Location,
  budget : ParameterBudget,
) -> Array[ResponseContract] raise AuthError {
  let fields = match value {
    None => return []
    Some(value) => object(value, at)
  }
  let result = []
  for status in sorted_keys(fields) {
    if status.has_prefix("x-") {
      continue
    }
    if status != "default" &&
      !(status.length() == 3 &&
      status[0] >= '1' &&
      status[0] <= '5' &&
      (
        (status[1] == 'X' && status[2] == 'X') ||
        (
          status[1] >= '0' &&
          status[1] <= '9' &&
          status[2] >= '0' &&
          status[2] <= '9'
        )
      )) {
      issue(
        "contract.response-status",
        "Invalid response status",
        at.key(status),
      )
    }
    let (response, location, _) = graph.resolve(fields[status], at.key(status))
    let content = media_content(
      graph,
      response.get("content"),
      location.key("content"),
      budget,
    )
    let remainder = without(response, ["content", "description"])
    charge_contract(remainder, location, budget)
    if unevaluated_ref(remainder) {
      issue(
        "contract.unevaluated-ref", "Response header/link references are not yet resolved",
        location,
      )
    }
    result.push({ status, content, location, remainder: canonical(remainder), })
  }
  result
}
