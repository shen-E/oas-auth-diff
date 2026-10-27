///|
fn quote(text : String) -> String {
  Json::string(text).stringify()
}

///|
fn canonical(value : Value) -> String {
  match value {
    Str(text) => quote(text)
    Obj(obj) => {
      let fields = []
      for key in sorted_keys(obj) {
        if obj.get(key) is Some(value) {
          fields.push(quote(key) + ":" + canonical(value))
        }
      }
      "{" + fields.join(",") + "}"
    }
    Seq(items) => "[" + items.map(canonical).join(",") + "]"
    Null => "null"
    Bool(value) => value.to_string()
    Number => "0"
  }
}

///|
fn endpoint(
  obj : Map[String, Value],
  key : String,
  pointer : Location,
) -> Value raise AuthError {
  let url = required_string(obj, key, pointer)
  let prefix = if url.has_prefix("https://") {
    "https://"
  } else if url.has_prefix("http://") {
    "http://"
  } else {
    issue(
      "auth.url",
      "Authentication endpoints require absolute http/https URLs; relative URL resolution is unsupported",
      pointer.key(key),
    )
    abort("unreachable")
  }
  let authority = url
    .strip_prefix(prefix)
    .unwrap()
    .split("/")
    .next()
    .unwrap_or("")
  if authority.is_empty() ||
    url.iter().any(char => char.to_int() <= 32 || char.to_int() == 127) {
    issue("auth.url", "Invalid authentication endpoint URL", pointer.key(key))
  }
  Str(url)
}

///|
fn Context::scheme(
  self : Context,
  name : String,
  external~ : Bool = true,
) -> ParsedScheme raise AuthError {
  if self.cache.get(name) is Some(cached) {
    return cached
  }
  let pointer : Location = {
    uri: self.source,
    pointer: pointer_key("/components/securitySchemes", name),
  }
  let value = match self.declared.get(name) {
    Some(value) => value
    None => {
      issue("auth.scheme", "Undefined security scheme: " + name, pointer)
      abort("unreachable")
    }
  }
  let (obj, location) = self.graph.resolve(value, pointer, external~)
  let kind = required_string(obj, "type", location)
  let fingerprint : Map[String, Value] = { "type": Str(kind) }
  let scopes : Map[String, Bool] = Map([])
  match kind {
    "apiKey" => {
      let credential_name = required_string(obj, "name", location)
      let where_ = required_string(obj, "in", location)
      if where_ != "query" && where_ != "header" && where_ != "cookie" {
        issue(
          "auth.scheme",
          "apiKey location must be query, header or cookie",
          location.key("in"),
        )
      }
      fingerprint["in"] = Str(where_)
      fingerprint["name"] = Str(
        if where_ == "header" {
          credential_name.to_lower()
        } else {
          credential_name
        },
      )
    }
    "http" =>
      fingerprint["scheme"] = Str(
        required_string(obj, "scheme", location).to_lower(),
      )
    "openIdConnect" =>
      fingerprint["openIdConnectUrl"] = endpoint(
        obj, "openIdConnectUrl", location,
      )
    "mutualTLS" =>
      if self.minor != 1 {
        issue(
          "auth.scheme",
          "mutualTLS requires OpenAPI 3.1",
          location.key("type"),
        )
      }
    "oauth2" => {
      let flow_location = location.key("flows")
      let flows = match obj.get("flows") {
        Some(value) => object(value, flow_location)
        None => {
          issue("auth.required", "OAuth2 requires flows", flow_location)
          abort("unreachable")
        }
      }
      let flow_out = Map([])
      let mut flow_count = 0
      for flow_name in sorted_keys(flows) {
        if flow_name.has_prefix("x-") {
          continue
        }
        if flow_name != "implicit" &&
          flow_name != "password" &&
          flow_name != "clientCredentials" &&
          flow_name != "authorizationCode" {
          issue(
            "auth.scheme",
            "Unknown OAuth flow: " + flow_name,
            flow_location.key(flow_name),
          )
        }
        flow_count += 1
        let at = flow_location.key(flow_name)
        let flow = object(flows[flow_name], at)
        let selected = Map([])
        if flow_name == "implicit" || flow_name == "authorizationCode" {
          selected["authorizationUrl"] = endpoint(flow, "authorizationUrl", at)
        }
        if flow_name != "implicit" {
          selected["tokenUrl"] = endpoint(flow, "tokenUrl", at)
        }
        if flow.contains("refreshUrl") {
          selected["refreshUrl"] = endpoint(flow, "refreshUrl", at)
        }
        let scopes_at = at.key("scopes")
        let declared = match flow.get("scopes") {
          Some(value) => object(value, scopes_at)
          None => {
            issue(
              "auth.required", "OAuth flow requires a scopes object", scopes_at,
            )
            abort("unreachable")
          }
        }
        for scope, description in declared {
          let _ = string(description, scopes_at.key(scope))
          scopes[scope] = true
        }
        flow_out[flow_name] = Obj(selected)
      }
      if flow_count == 0 {
        issue("auth.scheme", "OAuth2 requires at least one flow", flow_location)
      }
      fingerprint["flows"] = Obj(flow_out)
    }
    _ =>
      issue(
        "auth.scheme",
        "Unsupported security scheme type: " + kind,
        location.key("type"),
      )
  }
  let parsed = {
    public_scheme: { name, fingerprint: canonical(Obj(fingerprint)), location, },
    kind,
    scopes,
  }
  self.cache[name] = parsed
  parsed
}

///|
fn Context::security(
  self : Context,
  value : Value,
  pointer : Location,
  charge~ : Bool = false,
) -> ParsedSecurity raise AuthError {
  let requirements = match value {
    Seq(items) => items
    _ => {
      issue("auth.type", "security must be an array", pointer)
      abort("unreachable")
    }
  }
  if requirements.length() > 256 {
    issue("auth.limit", "security exceeds 256 alternatives", pointer)
  }
  let alternatives = []
  let used = []
  let mut total = 0
  for index, requirement in requirements {
    let at = pointer.key(index.to_string())
    let obj = object(requirement, at)
    let atoms = []
    for name in sorted_keys(obj) {
      let scheme = self.scheme(name)
      if !used.contains(name) {
        used.push(name)
      }
      atoms.push(@logic.Credential(name))
      let names_at = at.key(name)
      let names = match obj[name] {
        Seq(names) => names
        _ => {
          issue(
            "auth.type", "Security requirement must contain an array of strings",
            names_at,
          )
          abort("unreachable")
        }
      }
      if names.length() > 1023 {
        issue("auth.limit", "Security alternative exceeds 1024 atoms", at)
      }
      for i, value in names {
        let value = string(value, names_at.key(i.to_string()))
        if scheme.kind == "oauth2" || scheme.kind == "openIdConnect" {
          if scheme.kind == "oauth2" && !scheme.scopes.contains(value) {
            issue(
              "auth.scope",
              "Undefined OAuth scope: " + value,
              names_at.key(i.to_string()),
            )
          }
          atoms.push(@logic.Scope(name, value))
        } else if self.minor == 1 {
          atoms.push(@logic.Role(name, value))
        } else {
          issue(
            "auth.role", "Non-OAuth requirements must be empty in OpenAPI 3.0", names_at,
          )
        }
      }
      if atoms.length() > 1024 {
        issue("auth.limit", "Security alternative exceeds 1024 atoms", at)
      }
    }
    total += atoms.length()
    if total > 8192 {
      issue("auth.limit", "security exceeds 8192 total atoms", pointer)
    }
    alternatives.push(atoms)
  }
  used.sort()
  if charge {
    self.graph.charge_atoms(total, pointer)
  }
  let policy = if requirements.is_empty() {
    @logic.Policy::anonymous()
  } else {
    @logic.Policy::new(alternatives)
  }
  { policy, schemes: used, atoms: total, }
}
