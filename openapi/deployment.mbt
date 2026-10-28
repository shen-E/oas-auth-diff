///|
fn explicit_document_url(
  url : String,
  location : Location,
) -> String raise DocumentError {
  try {
    identity_string(url, location)
    let normalized = resolve_http_url(url, None, location)
    identity_string(normalized, location)
    normalized
  } catch {
    AuthError(_, message, _) =>
      raise DocumentError(location.uri + ": " + message)
  }
}

///|
fn legacy_document_url(source : String) -> String? {
  if !http_source(source) {
    return None
  }
  Some(resolve_http_url(source, None, { uri: source, pointer: "", })) catch {
    _ => None
  }
}

///|
fn Graph::document_base(self : Graph, location : Location) -> String? {
  match self.documents.get(location.uri) {
    Some(cached) if cached.document_url is Some(_) => cached.document_url
    // Preserve the previous HTTP-source validation path without imposing a new
    // eager failure on callers that never need a relative server base.
    _ if !self.explicit_urls && http_source(location.uri) => Some(location.uri)
    _ => None
  }
}

///|
fn Graph::record_origin_edge(
  self : Graph,
  parent : String,
  child : String,
) -> Unit {
  if !self.explicit_urls {
    return
  }
  let children = match self.origin_children.get(parent) {
    Some(children) => children
    None => {
      let children = Map([])
      self.origin_children[parent] = children
      children
    }
  }
  children[child] = true
}

///|
fn Graph::propagate_origin_conflicts(self : Graph) -> Unit {
  let pending = self.conflicted_origins.keys().collect()
  let mut index = 0
  while index < pending.length() {
    if self.origin_children.get(pending[index]) is Some(children) {
      for child in children.keys() {
        if !self.conflicted_origins.contains(child) {
          self.conflicted_origins[child] = true
          pending.push(child)
        }
      }
    }
    index += 1
  }
}

///|
fn Context::bind_identity(
  self : Context,
  value : InstantiatedScheme,
  operation : Location?,
) -> Scheme {
  if operation is Some(location) {
    self.identity_origins[(location.uri, location.pointer, value.scheme.name)] = value.origins
  }
  value.scheme
}

///|
fn Context::invalidate_origins(
  self : Context,
  operation : Operation,
  diagnostics : Array[Diagnostic],
) -> Operation {
  let retained = []
  let mut used_conflict = false
  for identity in operation.scheme_identities {
    let origins = self.identity_origins
      .get((operation.location.uri, operation.location.pointer, identity.name))
      .unwrap_or([])
    if origins.any(origin => self.graph.conflicted_origins.contains(origin)) {
      if operation.schemes.contains(identity.name) {
        used_conflict = true
      }
    } else {
      retained.push(identity)
    }
  }
  if used_conflict {
    let location = match
      self.operation_servers.get(
        (operation.location.uri, operation.location.pointer),
      ) {
      Some(selection) => selection.location
      None => operation.security_location
    }
    diagnostics.push({
      code: "auth.base",
      message: "Relative server identity depends on a canonical source with conflicting document URLs",
      location,
    })
  }
  {
    ..operation,
    scheme_identities: retained,
    policy: if used_conflict {
      None
    } else {
      operation.policy
    },
  }
}
