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
  operation : (String, String)?,
) -> Scheme {
  if operation is Some((verb, path)) {
    self.identity_origins[(verb, path, value.scheme.name)] = value.origins
    self.identity_contents[(verb, path, value.scheme.name)] = value.contents
  }
  value.scheme
}

///|
fn Context::operation_ready(self : Context, operation : Operation) -> Bool {
  if operation.policy is None {
    return false
  }
  let key = (operation.http_method, operation.path)
  if self.operation_contents
    .get(key)
    .unwrap_or([])
    .any(source => self.graph.conflicted_contents.contains(source)) {
    return false
  }
  for name in operation.schemes {
    let identity = (operation.http_method, operation.path, name)
    if self.identity_contents
      .get(identity)
      .unwrap_or([])
      .any(source => self.graph.conflicted_contents.contains(source)) {
      return false
    }
    if self.identity_origins
      .get(identity)
      .unwrap_or([])
      .any(source => self.graph.conflicted_origins.contains(source)) {
      return false
    }
  }
  true
}

///|
fn Context::invalidate_dependencies(
  self : Context,
  operation : Operation,
  diagnostics : Array[Diagnostic],
) -> Operation {
  let content_conflict = self.operation_contents
    .get((operation.http_method, operation.path))
    .unwrap_or([])
    .any(source => self.graph.conflicted_contents.contains(source))
  let retained = []
  let mut used_content = false
  let mut used_origin = false
  for identity in operation.scheme_identities {
    let key = (operation.http_method, operation.path, identity.name)
    let invalid_content = self.identity_contents
      .get(key)
      .unwrap_or([])
      .any(source => self.graph.conflicted_contents.contains(source))
    let invalid_origin = self.identity_origins
      .get(key)
      .unwrap_or([])
      .any(source => self.graph.conflicted_origins.contains(source))
    if invalid_content || invalid_origin {
      if operation.schemes.contains(identity.name) {
        if invalid_content {
          used_content = true
        }
        if invalid_origin {
          used_origin = true
        }
      }
    } else if !content_conflict {
      retained.push(identity)
    }
  }
  if content_conflict || used_content {
    diagnostics.push({
      code: "ref.conflict",
      message: "Operation authentication depends on a canonical source with conflicting content or encoding",
      location: operation.location,
    })
  }
  if used_origin {
    let location = match
      self.operation_servers.get((operation.http_method, operation.path)) {
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
    policy: if content_conflict || used_content || used_origin {
      None
    } else {
      operation.policy
    },
  }
}
