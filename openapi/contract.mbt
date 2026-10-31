///|
/// Parse a lossless snapshot and extract effective request/response contracts.
/// References use the same bounded, caller-controlled loader as authentication.
pub fn parse_specification(
  text : String,
  format~ : InputFormat,
  source~ : String = "<input>",
  load~ : ((String, String) -> SourceDocument raise DocumentError)? = None,
) -> Specification raise DocumentError {
  let (root, nodes) = read_input(text, format)
  let fields = match root {
    Obj(fields) => fields
    _ => raise DocumentError("OpenAPI root must be an object")
  }
  let version = match fields.get("openapi") {
    Some(Str(version)) if minor_version(version) is Some(_) => version
    _ =>
      raise DocumentError("Expected an OpenAPI 3.0.x or 3.1.x version string")
  }
  let graph = source_graph(
    { text, format, source, },
    root,
    nodes,
    load,
    legacy_document_url(source),
  )
  let diagnostics = []
  if !version.has_prefix("3.0.") &&
    !contract_dialect(fields.get("jsonSchemaDialect")) {
    diagnostics.push({
      code: "contract.dialect",
      message: "Custom JSON Schema dialect assertions are not interpreted by the compatibility solver",
      location: { uri: source, pointer: "/jsonSchemaDialect", },
    })
  }
  let operations = []
  let budget = { count: 0, nodes: 0, legacy: version.has_prefix("3.0."), }
  let location : Location = { uri: source, pointer: "", }
  let paths = try {
    match fields.get("paths") {
      Some(value) => object(value, location.key("paths"))
      None if minor_version(version) == Some(1) => Map([])
      None => {
        issue(
          "contract.paths",
          "OpenAPI 3.0 requires paths",
          location.key("paths"),
        )
        abort("unreachable")
      }
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error))
      Map([])
    }
  }
  for path in analyzable_paths(paths, location.key("paths"), diagnostics) {
    if operations.length() >= 10000 ||
      budget.count > 250000 ||
      budget.nodes > 1000000 {
      diagnostics.push({
        code: "resource.operations",
        message: "Contract extraction budget exhausted",
        location,
      })
      break
    }
    try {
      let (item, at, _) = graph.resolve(
        paths[path],
        location.key("paths").key(path),
      )
      for key in item.keys() {
        if ![
            "delete", "get", "head", "options", "patch", "post", "put", "trace",
            "parameters", "servers", "summary", "description",
          ].contains(key) &&
          !key.has_prefix("x-") {
          issue(
            "contract.path-item",
            "Unsupported Path Item field: " + key,
            at.key(key),
          )
        }
      }
      let inherited = parameters(
        graph,
        item.get("parameters"),
        at.key("parameters"),
        budget,
      )
      let context = without(item, [
        "delete", "get", "head", "options", "patch", "post", "put", "trace", "parameters",
        "summary", "description",
      ])
      charge_contract(context, at, budget)
      let path_context = canonical(context)
      for
        verb in [
          "delete", "get", "head", "options", "patch", "post", "put", "trace",
        ] {
        if item.get(verb) is Some(value) {
          if operations.length() >= 10000 {
            issue(
              "resource.operations", "Extraction exceeds 10000 operations", at,
            )
          }
          let operation_at = at.key(verb)
          let operation = contract_operation(
            graph,
            value,
            inherited,
            path,
            verb.to_upper(),
            operation_at,
            budget,
            path_context,
          ) catch {
            error => {
              diagnostics.push(diagnostic(error))
              {
                http_method: verb.to_upper(),
                path,
                parameters: [],
                request_body: None,
                responses: [],
                location: operation_at,
                complete: false,
                remainder: "",
              }
            }
          }
          operations.push(operation)
        }
      }
    } catch {
      error => diagnostics.push(diagnostic(error))
    }
  }
  for issue in graph.resource_diagnostics {
    if !diagnostics.contains(issue) {
      diagnostics.push(issue)
    }
  }
  if !graph.conflicted_contents.is_empty() ||
    !graph.conflicted_origins.is_empty() {
    diagnostics.push({
      code: "ref.conflict",
      message: "Referenced sources conflict",
      location,
    })
  }
  let remainder = match
    without(fields, ["paths", "info", "tags", "externalDocs"]) {
    Obj(result) => {
      if result.get("components") is Some(Obj(components)) {
        let retained = without(components, [
          "parameters", "schemas", "requestBodies", "responses", "headers",
        ])
        match retained {
          Obj(remaining) if remaining.is_empty() =>
            ignore(result.remove("components"))
          _ => result["components"] = retained
        }
      }
      canonical(Obj(result))
    }
    _ => abort("object expected")
  }
  { source, version, operations, diagnostics, root, remainder, }
}
