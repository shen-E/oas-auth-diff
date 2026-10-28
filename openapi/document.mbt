///|
fn diagnostic(error : AuthError) -> Diagnostic {
  let AuthError(code, message, location) = error
  { code, message, location, }
}

///|
fn minor_version(version : String) -> Int32? {
  let pieces = version.split(".").map(StringView::to_owned).collect()
  if pieces.length() != 3 || pieces[0] != "3" || pieces[2].is_empty() {
    return None
  }
  if !pieces[2].iter().all(c => c >= '0' && c <= '9') {
    return None
  }
  match pieces[1] {
    "0" => Some(0)
    "1" => Some(1)
    _ => None
  }
}

///|
fn Context::operation(
  self : Context,
  value : Value,
  verb : String,
  path : String,
  location : Location,
  inherited : ParsedSecurity?,
  inherited_location : Location,
  path_servers : ServerSelection?,
  contents : Array[String],
  diagnostics : Array[Diagnostic],
) -> Operation {
  let operation_key = (verb.to_upper(), path)
  self.operation_contents[operation_key] = contents
  let mut operation_id = None
  let mut policy = None
  let mut schemes = []
  let scheme_identities = []
  let mut security_location = location.key("security")
  try {
    let obj = object(value, location)
    if obj.contains("$ref") {
      issue(
        "auth.operation",
        "Operation Object does not support $ref; reference a Path Item instead",
        location.key("$ref"),
      )
    }
    if obj.get("operationId") is Some(value) {
      operation_id = Some(string(value, location.key("operationId")))
    }
    let selection = match obj.get("servers") {
      Some(value) => { value: Some(value), location: location.key("servers"), }
      None => path_servers.unwrap_or(self.entry_servers)
    }
    self.operation_servers[operation_key] = selection
    let parsed = match obj.get("security") {
      Some(value) => Some(self.security(value, security_location, charge=true))
      None => {
        security_location = inherited_location
        if inherited is Some(parsed) {
          self.graph.charge_atoms(parsed.atoms, security_location)
        }
        inherited
      }
    }
    if parsed is Some(parsed) {
      schemes = parsed.schemes.copy()
      for name in schemes {
        scheme_identities.push(
          self.identity(
            name,
            selection,
            used=true,
            operation=Some(operation_key),
          ),
        )
      }
      policy = Some(parsed.policy)
    }
  } catch {
    error => diagnostics.push(diagnostic(error))
  }
  {
    http_method: verb.to_upper(),
    path,
    operation_id,
    policy,
    location,
    security_location,
    schemes,
    scheme_identities,
  }
}

///|
/// Parse one OpenAPI 3.0/3.1 entry document without loading external sources.
/// Authentication failures retain unaffected operations and produce diagnostics.
/// Use `parse_with_loader` to enable controlled relative-file references.
pub fn parse_document(
  text : String,
  format~ : InputFormat,
  source~ : String = "<input>",
  document_url~ : String? = None,
) -> Document raise DocumentError {
  parse_entry(text, format~, source~, load=None, document_url~)
}

///|
/// Parse an entry document with caller-controlled relative-file loading.
///
/// The callback receives the referring source identity and a percent-decoded
/// relative path without a fragment. It returns a canonical source identity.
/// Local references use the current source; security names and inherited global
/// security retain the entry document's meaning throughout the graph.
pub fn parse_with_loader(
  text : String,
  format~ : InputFormat,
  source~ : String,
  load~ : (String, String) -> SourceDocument raise DocumentError,
  document_url~ : String? = None,
) -> Document raise DocumentError {
  parse_entry(text, format~, source~, load=Some(load), document_url~)
}

///|
fn prepare_entry(
  text : String,
  format~ : InputFormat,
  source~ : String,
  load~ : ((String, String) -> SourceDocument raise DocumentError)?,
  document_url~ : String?,
) -> LiveDocument raise DocumentError {
  let effective_url = match document_url {
    Some(url) => Some(explicit_document_url(url, { uri: source, pointer: "", }))
    None => legacy_document_url(source)
  }
  let (root, nodes) = read_input(text, format) catch {
    DocumentError(message) => raise DocumentError(source + ": " + message)
  }
  let obj = match root {
    Obj(obj) => obj
    _ => raise DocumentError(source + ": OpenAPI root must be an object")
  }
  let minor = match obj.get("openapi") {
    Some(Str(version)) =>
      match minor_version(version) {
        Some(minor) => minor
        None =>
          raise DocumentError(
            source + ": Supported OpenAPI versions are 3.0.x and 3.1.x",
          )
      }
    _ =>
      raise DocumentError(
        source + ": openapi must be a 3.0.x or 3.1.x version string",
      )
  }
  let entry_location : Location = { uri: source, pointer: "", }
  let graph : Graph = {
    documents: Map([]),
    requests: Map([]),
    load,
    resource_diagnostics: [],
    explicit_urls: document_url is Some(_),
    conflicted_origins: Map([]),
    conflicted_contents: Map([]),
    origin_children: Map([]),
    bytes: @utf8.encode(text).length(),
    nodes,
    operations: 0,
    atoms: 0,
  }
  graph.documents[source] = {
    input: { text, format, source, },
    value: Ok(root),
    document_url: effective_url,
  }
  let diagnostics = []
  let declared = try {
    match obj.get("components") {
      None => Map([])
      Some(value) => {
        let location = entry_location.key("components")
        let components = object(value, location)
        match components.get("securitySchemes") {
          None => Map([])
          Some(value) => object(value, location.key("securitySchemes"))
        }
      }
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error))
      Map([])
    }
  }
  let context : Context = {
    source,
    minor,
    declared,
    cache: Map([]),
    scheme_failures: Map([]),
    graph,
    entry_servers: {
      value: obj.get("servers"),
      location: entry_location.key("servers"),
    },
    operation_servers: Map([]),
    identity_origins: Map([]),
    identity_contents: Map([]),
    operation_contents: Map([]),
    servers_cache: Map([]),
    identities_cache: Map([]),
    used_identities: 0,
    unused_identities: 0,
    unused_attempts: 0,
    used_identity_bytes: 0,
    unused_identity_bytes: 0,
  }
  let inherited_location = if obj.contains("security") {
    entry_location.key("security")
  } else {
    entry_location
  }
  let inherited = try {
    match obj.get("security") {
      None =>
        Some({ policy: @logic.Policy::anonymous(), schemes: [], atoms: 0, })
      Some(value) => Some(context.security(value, inherited_location))
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error))
      None
    }
  }
  let paths = try {
    match obj.get("paths") {
      Some(value) => object(value, entry_location.key("paths"))
      None => {
        if minor == 0 {
          issue(
            "auth.required",
            "OpenAPI 3.0 requires paths",
            entry_location.key("paths"),
          )
        }
        Map([])
      }
    }
  } catch {
    error => {
      diagnostics.push(diagnostic(error))
      Map([])
    }
  }
  let operations = []
  let methods = [
    "delete", "get", "head", "options", "patch", "post", "put", "trace",
  ]
  let mut exhausted = false
  for path in analyzable_paths(paths, entry_location.key("paths"), diagnostics) {
    if exhausted {
      break
    }
    let location = entry_location.key("paths").key(path)
    try {
      let (item, resolved_location, contents) = graph.resolve(
        paths[path],
        location,
      )
      for key in item.keys() {
        if !methods.contains(key) &&
          key != "summary" &&
          key != "description" &&
          key != "servers" &&
          key != "parameters" &&
          !key.has_prefix("x-") {
          issue(
            "ref.target",
            "Unsupported Path Item field: " + key,
            resolved_location.key(key),
          )
        }
      }
      let path_servers = match item.get("servers") {
        Some(value) =>
          Some({
            value: Some(value),
            location: resolved_location.key("servers"),
          })
        None => None
      }
      for verb in methods {
        if item.get(verb) is Some(value) {
          if graph.operations >= 10000 {
            exhausted = true
            issue(
              "resource.operations",
              "Extraction exceeds 10000 operations",
              resolved_location.key(verb),
            )
          }
          graph.operations += 1
          operations.push(
            context.operation(
              value,
              verb,
              path,
              resolved_location.key(verb),
              inherited,
              inherited_location,
              path_servers,
              contents,
              diagnostics,
            ),
          )
        }
      }
    } catch {
      error => diagnostics.push(diagnostic(error))
    }
  }
  { context, operations, diagnostics, document_url: effective_url, }
}

///|
fn parse_entry(
  text : String,
  format~ : InputFormat,
  source~ : String,
  load~ : ((String, String) -> SourceDocument raise DocumentError)?,
  document_url~ : String?,
) -> Document raise DocumentError {
  finalize_entry(prepare_entry(text, format~, source~, load~, document_url~))
}

///|
fn finalize_entry(live : LiveDocument) -> Document {
  let context = live.context
  let operations = live.operations
  let diagnostics = live.diagnostics
  let graph = context.graph
  let source = context.source
  let declared = context.declared
  let effective_url = live.document_url
  graph.propagate_origin_conflicts()
  // All used identities are charged before best-effort unused work begins.
  for index in 0..<operations.length() {
    operations[index] = context.complete_unused_identities(operations[index])
  }
  // Export local unused declarations without implicitly reading more files.
  // Used external declarations have already been loaded and cached above.
  for name in sorted_keys(declared) {
    ignore(context.scheme(name, external=false)) catch {
      _ => ()
    }
  }
  for item in graph.resource_diagnostics {
    if !diagnostics.any(existing => {
        existing.code == item.code && existing.location == item.location
      }) {
      diagnostics.push(item)
    }
  }
  for index in 0..<operations.length() {
    operations[index] = context.invalidate_dependencies(
      operations[index],
      diagnostics,
    )
  }
  let schemes = []
  for name in sorted_keys(context.cache) {
    let parsed = context.cache[name]
    if !parsed.contents.any(source => graph.conflicted_contents.contains(source)) {
      schemes.push(parsed.public_scheme)
    }
  }
  { source, document_url: effective_url, operations, schemes, diagnostics, }
}
