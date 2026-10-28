///|
fn Graph::failure(
  self : Graph,
  code : String,
  message : String,
  location : Location,
) -> LoadFailure {
  if code.has_prefix("resource.") &&
    !self.resource_diagnostics.any(item => item.code == code) {
    self.resource_diagnostics.push({ code, message, location, })
  }
  { code, message, }
}

///|
fn Graph::load_source(
  self : Graph,
  path : String,
  raw_path : String,
  location : Location,
) -> Result[String, LoadFailure] {
  if self.documents.length() >= 64 {
    return Err(
      self.failure(
        "resource.documents", "Reference graph exceeds 64 documents including the entry document",
        location,
      ),
    )
  }
  if self.nodes >= 1000000 {
    return Err(
      self.failure(
        "resource.nodes", "Reference graph exceeds 1000000 AST nodes", location,
      ),
    )
  }
  let derived_url = if self.explicit_urls {
    identity_string(raw_path, location) catch {
      AuthError(_, message, _) => return Err({ code: "ref.url", message, })
    }
    let parent_url = match self.documents.get(location.uri) {
      Some(cached) => cached.document_url
      None => None
    }
    let url = resolve_http_url(raw_path, parent_url, location) catch {
      AuthError(_, message, _) => return Err({ code: "ref.url", message, })
    }
    identity_string(url, location) catch {
      AuthError(_, message, _) => return Err({ code: "ref.url", message, })
    }
    Some(url)
  } else {
    None
  }
  let load = match self.load {
    Some(load) => load
    None => abort("loader is absent")
  }
  let input = load(location.uri, path) catch {
    error => return Err({ code: "ref.load", message: error.to_string(), })
  }
  if input.source.is_empty() {
    return Err({
      code: "ref.source",
      message: "Loader returned an empty canonical source identity",
    })
  }
  let document_url = if self.explicit_urls {
    derived_url
  } else {
    legacy_document_url(input.source)
  }
  if self.documents.get(input.source) is Some(cached) {
    self.record_origin_edge(location.uri, input.source)
    let origin_conflict = cached.document_url != document_url
    let content_conflict = cached.input.text != input.text ||
      cached.input.format != input.format
    if origin_conflict {
      self.conflicted_origins[input.source] = true
    }
    if content_conflict {
      self.conflicted_contents[input.source] = true
    }
    if origin_conflict || content_conflict {
      return Err({
        code: "ref.conflict",
        message: if content_conflict {
          "Canonical source has conflicting content or format: " + input.source
        } else {
          "Canonical source has conflicting document URLs: " + input.source
        },
      })
    }
    return match cached.value {
      Ok(_) => Ok(input.source)
      Err(failure) => Err(failure)
    }
  }
  let bytes = @utf8.encode(input.text).length()
  if bytes > 16 * 1024 * 1024 {
    return Err({
      code: "ref.input",
      message: input.source + ": Input exceeds 16 MiB",
    })
  }
  if bytes > 64 * 1024 * 1024 - self.bytes {
    return Err(
      self.failure(
        "resource.bytes", "Reference graph exceeds 64 MiB of encoded source", location,
      ),
    )
  }
  // Reserve source bytes before parsing; malformed sources are cached too.
  self.bytes += bytes
  let remaining = 1000000 - self.nodes
  let value = try {
    let (root, nodes) = read_input(
      input.text,
      input.format,
      node_limit=remaining.min(250000),
    )
    self.nodes += nodes
    Ok(root)
  } catch {
    error => {
      let reason = error.to_string()
      let message = input.source + ": " + reason
      if remaining < 250000 &&
        reason.has_prefix("Input exceeds remaining aggregate node budget") {
        self.nodes = 1000000
        Err(self.failure("resource.nodes", message, location))
      } else {
        Err({ code: "ref.input", message, })
      }
    }
  }
  self.documents[input.source] = { input, value, document_url, }
  self.record_origin_edge(location.uri, input.source)
  match value {
    Ok(_) => Ok(input.source)
    Err(failure) => Err(failure)
  }
}

///|
fn Graph::load_relative(
  self : Graph,
  path : String,
  raw_path : String,
  location : Location,
) -> String raise AuthError {
  let requests = match self.requests.get(location.uri) {
    Some(requests) => requests
    None => {
      let requests = Map([])
      self.requests[location.uri] = requests
      requests
    }
  }
  let key = if self.explicit_urls { raw_path } else { path }
  let result = match requests.get(key) {
    Some(result) => result
    None => {
      let result = self.load_source(path, raw_path, location)
      requests[key] = result
      result
    }
  }
  match result {
    Ok(uri) => uri
    Err(failure) => {
      issue(failure.code, failure.message, location)
      abort("unreachable")
    }
  }
}

///|
fn Graph::charge_atoms(
  self : Graph,
  count : Int32,
  location : Location,
) -> Unit raise AuthError {
  if count > 250000 - self.atoms {
    issue(
      "resource.atoms", "Expanded authentication exceeds 250000 atoms across operations",
      location,
    )
  }
  self.atoms += count
}
