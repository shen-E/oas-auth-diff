///|
fn Context::charge_identity_tuples(
  self : Context,
  count : Int32,
  used : Bool,
  location : Location,
) -> Unit raise AuthError {
  let current = if used { self.used_identities } else { self.unused_identities }
  if count > 100000 - current {
    issue(
      "resource.identities", "Authentication identity expansion exceeds 100000 tuples",
      location,
    )
  }
  if used {
    self.used_identities += count
  } else {
    self.unused_identities += count
  }
}

///|
fn Context::check_identity_bytes(
  self : Context,
  count : Int32,
  used : Bool,
  location : Location,
) -> Unit raise AuthError {
  if count > 1024 * 1024 {
    issue(
      "resource.identities", "One authentication identity exceeds 1 MiB", location,
    )
  }
  let current = if used {
    self.used_identity_bytes
  } else {
    self.unused_identity_bytes
  }
  let limit = if used { 32 * 1024 * 1024 } else { 8 * 1024 * 1024 }
  if count > limit - current {
    issue(
      "resource.identities", "Serialized authentication identities exceed the entry byte budget",
      location,
    )
  }
}

///|
fn Context::charge_identity_bytes(
  self : Context,
  count : Int32,
  used : Bool,
  location : Location,
) -> Unit raise AuthError {
  self.check_identity_bytes(count, used, location)
  if used {
    self.used_identity_bytes += count
  } else {
    self.unused_identity_bytes += count
  }
}

///|
fn Context::identity(
  self : Context,
  name : String,
  selection : ServerSelection,
  used~ : Bool,
  external~ : Bool = true,
  operation~ : (String, String)? = None,
  prepaid~ : Bool = false,
) -> Scheme raise AuthError {
  let parsed = self.scheme(name, external~)
  let key = if parsed.relative {
    (name, selection.location.uri, selection.location.pointer)
  } else {
    (name, "", "")
  }
  if self.identities_cache.get(key) is Some(result) {
    return match result {
      Ok(cached) => {
        self.charge_identity_tuples(
          cached.tuples - (if prepaid { 1 } else { 0 }),
          used,
          parsed.public_scheme.location,
        )
        self.charge_identity_bytes(
          cached.bytes,
          used,
          parsed.public_scheme.location,
        )
        self.bind_identity(cached, operation)
      }
      Err(error) => raise error
    }
  }
  let instantiated = try {
    let location = parsed.public_scheme.location
    let (fingerprint, tuples, origins) = if !parsed.relative {
      self.charge_identity_tuples(if prepaid { 0 } else { 1 }, used, location)
      (
        "{\"variants\":[{\"configuration\":" +
        parsed.public_scheme.fingerprint +
        ",\"variables\":{},\"default\":true}]}",
        1,
        [],
      )
    } else {
      let set = self.server_set(selection)
      self.charge_identity_tuples(
        set.variants.length() - (if prepaid { 1 } else { 0 }),
        used,
        selection.location,
      )
      let mut metadata_bytes = 0
      for variant in set.variants {
        metadata_bytes += variant.domain_bytes
        self.check_identity_bytes(metadata_bytes, used, selection.location)
      }
      let unique : Map[String, Bool] = Map([])
      let mut bytes = 16
      for variant in set.variants {
        let configuration = instantiate_template(
          parsed.template,
          variant.base,
          location,
        )
        let configuration = canonical(configuration)
        let tuple_bytes = @utf8.encode(configuration).length() +
          variant.domain_bytes +
          64
        self.check_identity_bytes(bytes + tuple_bytes, used, selection.location)
        let tuple = "{\"configuration\":" +
          configuration +
          ",\"variables\":" +
          variant.domain_fingerprint +
          ",\"default\":" +
          variant.is_default.to_string() +
          "}"
        if !unique.contains(tuple) {
          bytes += @utf8.encode(tuple).length() + 1
          self.check_identity_bytes(bytes, used, selection.location)
          unique[tuple] = true
        }
      }
      (
        "{\"variants\":[" + sorted_keys(unique).join(",") + "]}",
        set.variants.length(),
        set.origins,
      )
    }
    let bytes = @utf8.encode(fingerprint).length()
    self.charge_identity_bytes(bytes, used, location)
    Ok({
      scheme: { ..parsed.public_scheme, fingerprint, },
      tuples,
      bytes,
      origins,
      contents: parsed.contents,
    })
  } catch {
    error => Err(error)
  }
  self.identities_cache[key] = instantiated
  match instantiated {
    Ok(value) => self.bind_identity(value, operation)
    Err(error) => raise error
  }
}

///|
fn Context::complete_unused_identities(
  self : Context,
  operation : Operation,
) -> Operation {
  if !self.operation_ready(operation) || self.unused_attempts >= 100000 {
    return operation
  }
  let selection = match
    self.operation_servers.get((operation.http_method, operation.path)) {
    Some(selection) => selection
    None => return operation
  }
  let identities = operation.scheme_identities.copy()
  let present : Map[String, Bool] = Map([])
  for identity in identities {
    present[identity.name] = true
  }
  for name in sorted_keys(self.declared) {
    if self.unused_attempts >= 100000 {
      break
    }
    self.unused_attempts += 1
    if present.contains(name) {
      continue
    }
    identities.push(
      self.identity(
        name,
        selection,
        used=false,
        external=false,
        operation=Some((operation.http_method, operation.path)),
      ),
    ) catch {
      _ => ()
    }
  }
  { ..operation, scheme_identities: identities, }
}
