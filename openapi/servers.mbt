///|
fn server_parts(
  url : String,
  location : Location,
) -> (Array[ServerPart], Array[String]) raise AuthError {
  identity_string(url, location)
  let parts = []
  let variables = []
  let chars = url.to_array()
  let mut literal = StringBuilder()
  let mut index = 0
  while index < chars.length() {
    match chars[index] {
      '{' => {
        parts.push(Literal(literal.to_string()))
        literal = StringBuilder()
        index += 1
        let name = StringBuilder()
        while index < chars.length() && chars[index] != '}' {
          if chars[index] == '{' {
            issue(
              "auth.variable", "Nested server variable braces are unsupported", location,
            )
          }
          name.write_char(chars[index])
          index += 1
        }
        if index == chars.length() || name.to_string().is_empty() {
          issue(
            "auth.variable", "Unterminated or empty server variable", location,
          )
        }
        let name = name.to_string()
        if !variables.contains(name) {
          variables.push(name)
        }
        parts.push(Variable(name))
      }
      '}' =>
        issue(
          "auth.variable", "Unmatched server variable closing brace", location,
        )
      char => literal.write_char(char)
    }
    index += 1
  }
  parts.push(Literal(literal.to_string()))
  if variables.length() > 16 {
    issue(
      "resource.servers", "Server exceeds 16 referenced variables", location,
    )
  }
  variables.sort()
  (parts, variables)
}

///|
fn substitute_server(
  parts : Array[ServerPart],
  values : Map[String, String],
  location : Location,
) -> String raise AuthError {
  let out = StringBuilder()
  let mut bytes = 0
  for part in parts {
    let text = match part {
      Literal(text) => text
      Variable(name) => values[name]
    }
    bytes += @utf8.encode(text).length()
    if bytes > 8192 {
      issue(
        "resource.identities", "Expanded server URI exceeds 8192 bytes", location,
      )
    }
    out.write_string(text)
  }
  out.to_string()
}

///|
fn server_base(
  url : String,
  location : Location,
  graph : Graph,
) -> String raise AuthError {
  if relative_uri(url) {
    let base = graph.document_base(location)
    if base is None {
      issue(
        "auth.base", "Relative server URL requires an explicit HTTP(S) document source",
        location,
      )
    }
    resolve_http_url(url, base, location)
  } else {
    resolve_http_url(url, None, location)
  }
}

///|
fn expand_server(
  value : Value,
  location : Location,
  graph : Graph,
) -> (Array[ServerVariant], Array[String]) raise AuthError {
  let obj = object(value, location)
  let at = location.key("url")
  let url = required_string(obj, "url", location)
  let (parts, variables) = server_parts(url, at)
  let declarations = if variables.is_empty() {
    Map([])
  } else {
    match obj.get("variables") {
      Some(value) => object(value, location.key("variables"))
      None => {
        issue(
          "auth.variable", "Server variables require finite enum declarations", at,
        )
        abort("unreachable")
      }
    }
  }
  let domain = Map([])
  let mut domain_estimate = 2
  let defaults : Map[String, String] = Map([])
  let mut assignments : Array[Map[String, String]] = [Map([])]
  for name in variables {
    let variable_at = location.key("variables").key(name)
    let definition = match declarations.get(name) {
      Some(value) => object(value, variable_at)
      None => {
        issue(
          "auth.variable",
          "Undefined server variable: " + name,
          variable_at,
        )
        abort("unreachable")
      }
    }
    let default = match definition.get("default") {
      Some(value) => string(value, variable_at.key("default"))
      None => {
        issue(
          "auth.variable",
          "Server variable requires a string default",
          variable_at.key("default"),
        )
        abort("unreachable")
      }
    }
    identity_string(default, variable_at.key("default"))
    domain_estimate += @utf8.encode(quote(name)).length() +
      @utf8.encode(quote(default)).length() +
      32
    let values = match definition.get("enum") {
      Some(Seq(values)) if !values.is_empty() => values
      _ => {
        issue(
          "auth.variable",
          "Server variable requires a non-empty finite enum",
          variable_at.key("enum"),
        )
        abort("unreachable")
      }
    }
    let unique : Map[String, Bool] = Map([])
    for index, value in values {
      let text = string(value, variable_at.key("enum").key(index.to_string()))
      identity_string(text, variable_at.key("enum").key(index.to_string()))
      if !unique.contains(text) {
        domain_estimate += @utf8.encode(quote(text)).length() + 1
        if domain_estimate > 1024 * 1024 {
          issue(
            "resource.identities", "Server variable metadata exceeds 1 MiB", variable_at,
          )
        }
        unique[text] = true
      }
      if unique.length() > 64 {
        issue(
          "resource.servers",
          "Server variable exceeds 64 distinct values",
          variable_at.key("enum"),
        )
      }
    }
    if !unique.contains(default) {
      issue(
        "auth.variable",
        "Server variable default must belong to its enum",
        variable_at.key("default"),
      )
    }
    let values = sorted_keys(unique)
    if assignments.length() > 64 / values.length() {
      issue("resource.servers", "Server expansion exceeds 64 variants", at)
    }
    domain[name] = Obj({
      "default": Str(default),
      "enum": Seq(values.map(value => Str(value))),
    })
    defaults[name] = default
    let next = []
    for assignment in assignments {
      for value in values {
        let copy = assignment.copy()
        copy[name] = value
        next.push(copy)
      }
    }
    assignments = next
  }
  let domain_fingerprint = canonical(Obj(domain))
  let domain_bytes = @utf8.encode(domain_fingerprint).length()
  let out = []
  let origins = []
  for assignment in assignments {
    let rendered = substitute_server(parts, assignment, at)
    let base = server_base(rendered, at, graph)
    if relative_uri(rendered) && !origins.contains(at.uri) {
      origins.push(at.uri)
    }
    identity_string(base, at)
    out.push({
      base,
      domain_fingerprint,
      domain_bytes,
      is_default: variables.all(name => assignment[name] == defaults[name]),
    })
  }
  (out, origins)
}

///|
fn server_set(
  selection : ServerSelection,
  graph : Graph,
) -> ServerSet raise AuthError {
  let entries = match selection.value {
    None => []
    Some(Seq(entries)) => entries
    _ => {
      issue("auth.server", "servers must be an array", selection.location)
      abort("unreachable")
    }
  }
  if entries.length() > 64 {
    issue("resource.servers", "servers exceeds 64 entries", selection.location)
  }
  if entries.is_empty() {
    return {
      variants: [
        {
          base: server_base("/", selection.location, graph),
          domain_fingerprint: "{}",
          domain_bytes: 2,
          is_default: true,
        },
      ],
      origins: [selection.location.uri],
    }
  }
  let variants = []
  let origins = []
  for index, entry in entries {
    let (expanded, dependencies) = expand_server(
      entry,
      selection.location.key(index.to_string()),
      graph,
    )
    for origin in dependencies {
      if !origins.contains(origin) {
        origins.push(origin)
      }
    }
    if expanded.length() > 64 - variants.length() {
      issue(
        "resource.servers",
        "Operation exceeds 64 expanded server variants",
        selection.location,
      )
    }
    for variant in expanded {
      variants.push(variant)
    }
  }
  { variants, origins, }
}

///|
fn Context::server_set(
  self : Context,
  selection : ServerSelection,
) -> ServerSet raise AuthError {
  let key = (selection.location.uri, selection.location.pointer)
  let result = match self.servers_cache.get(key) {
    Some(result) => result
    None => {
      let result = Ok(server_set(selection, self.graph)) catch {
        error => Err(error)
      }
      self.servers_cache[key] = result
      result
    }
  }
  match result {
    Ok(set) => set
    Err(error) => raise error
  }
}
