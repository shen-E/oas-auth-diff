///|
fn response_headers(
  graph : Graph,
  value : Value?,
  at : Location,
  budget : ParameterBudget,
) -> Array[HeaderContract] raise AuthError {
  let fields = match value {
    None => return []
    Some(value) => object(value, at)
  }
  let result = []
  let seen = Map([])
  for name in sorted_keys(fields) {
    let key = name.to_lower()
    if key == "content-type" {
      continue
    }
    if key.is_empty() ||
      !key
      .iter()
      .all(c => {
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||
        "!#$%&'*+-.^_`|~".contains(c.to_string())
      }) {
      issue(
        "contract.header-name",
        "Invalid response header name",
        at.key(name),
      )
    }
    if seen.contains(key) {
      issue(
        "contract.header-duplicate",
        "Duplicate response header ignoring case",
        at.key(name),
      )
    }
    seen[key] = true
    let (header, location, _) = graph.resolve(fields[name], at.key(name))
    if header.contains("name") || header.contains("in") {
      issue(
        "contract.header-field", "Header Object must not declare name or in", location,
      )
    }
    let required = match header.get("required") {
      None => false
      Some(Bool(required)) => required
      _ => {
        issue(
          "contract.header-required",
          "Header required must be a boolean",
          location.key("required"),
        )
        abort("unreachable")
      }
    }
    if header.contains("schema") && header.contains("content") {
      issue(
        "contract.header-schema", "Header cannot declare both schema and content",
        location,
      )
    }
    let schema = extract_schema(
      graph,
      header.get("schema"),
      location.key("schema"),
      budget,
    )
    let content = media_content(
      graph,
      header.get("content"),
      location.key("content"),
      budget,
    )
    if header.contains("content") && content.length() != 1 {
      issue(
        "contract.header-content",
        "Header content must have exactly one media type",
        location.key("content"),
      )
    }
    let remainder = without(header, [
      "description", "required", "schema", "content", "example", "examples", "deprecated",
    ])
    charge_contract(remainder, location, budget)
    if unevaluated_ref(remainder) {
      issue(
        "contract.unevaluated-ref", "Unresolved response header field", location,
      )
    }
    result.push({
      name,
      required,
      schema,
      content,
      location,
      remainder: canonical(remainder),
    })
  }
  result
}
