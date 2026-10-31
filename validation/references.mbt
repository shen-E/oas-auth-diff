///|
priv struct Walk {
  resolver : @openapi.ReferenceResolver
  resources : Map[String, Json]
  validators : Map[String, @metaschema.Schema]
  legacy : Bool
  seen : Map[(String, String, String, String), Bool]
  active : Map[(String, String, String, String), Bool]
  document_dialects : Map[String, String?]
  violations : Array[Violation]
  diagnostics : Array[@openapi.Diagnostic]
  mut remaining : Int32
}

///|
fn Walk::target_dialect(
  self : Walk,
  at : @openapi.Location,
  inherited : String,
) -> String {
  if !self.document_dialects.contains(at.uri) {
    let declared = match self.resolver.resolve("#", at) {
      Ok((Object(root), _)) if root.get("openapi") is Some(String(version)) &&
        version.has_prefix("3.1.") &&
        root.get("jsonSchemaDialect") is Some(String(uri)) => Some(uri)
      _ => None
    }
    self.document_dialects[at.uri] = declared
  }
  self.document_dialects[at.uri].unwrap_or(inherited)
}

///|
fn Walk::diagnostic(
  self : Walk,
  code : String,
  message : String,
  at : @openapi.Location,
) -> Unit {
  if self.diagnostics.length() < 1000 &&
    !self.diagnostics.any(d => d.code == code && d.location == at) {
    self.diagnostics.push({ code, message, location: at, })
  }
}

///|
fn Walk::validator(
  self : Walk,
  kind : String,
  dialect : String,
  at : @openapi.Location,
) -> @metaschema.Schema? {
  let key = if kind == "schema" && !self.legacy { dialect } else { kind }
  if self.validators.get(key) is Some(validator) {
    return Some(validator)
  }
  let value = if kind == "schema" && !self.legacy {
    match self.resources.get(dialect) {
      Some(resource) => resource
      None => {
        self.diagnostic(
          "validation.dialect",
          "Schema dialect is not supplied: " + dialect,
          at,
        )
        return None
      }
    }
  } else {
    let name = if self.legacy {
      match kind {
        "path-item" => "PathItem"
        "request-body" => "RequestBody"
        "security-scheme" => "SecurityScheme"
        "callback" => "Callback"
        "schema" => "Schema"
        "parameter" => "Parameter"
        "header" => "Header"
        "response" => "Response"
        "example" => "Example"
        "link" => "Link"
        _ => return None
      }
    } else if kind == "callback" {
      "callbacks"
    } else {
      kind
    }
    let base = if self.legacy {
      "https://spec.openapis.org/oas/3.0/schema/2024-10-18#/definitions/"
    } else {
      "https://spec.openapis.org/oas/3.1/schema/2025-09-15#/$defs/"
    }
    { "$ref": base + name }
  }
  let validator = @metaschema.Schema::new(
    value,
    draft=if self.legacy { @metaschema.Draft4 } else { @metaschema.Draft2020 },
    remotes=self.resources,
  ) catch {
    error => {
      self.diagnostic("validation.metaschema", error.to_string(), at)
      return None
    }
  }
  self.validators[key] = validator
  Some(validator)
}

///|
fn Walk::check_bounds(
  self : Walk,
  value : Json,
  at : @openapi.Location,
  kind : String,
  dialect : String,
) -> Unit {
  if kind == "schema" &&
    (self.legacy || standard_assertions(dialect, self.resources)) &&
    value is Object(fields) {
    let assertions = Map([])
    for
      keyword in [
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength",
        "maxLength", "minItems", "maxItems", "minProperties", "maxProperties",
      ] {
      if fields.get(keyword) is Some(value) {
        assertions[keyword] = value
      }
    }
    ignore(@schema.parse(Json::object(assertions), openapi_30=self.legacy)) catch {
      @schema.SchemaError(message) =>
        if self.violations.length() < 1000 {
          self.violations.push({
            keyword: "schemaConstraints",
            message,
            location: at,
            schema_pointer: "",
          })
        } else {
          self.diagnostic(
            "resource.validation-results", "Validation exceeds 1000 reported violations",
            at,
          )
        }
    }
  }
}

///|
fn Walk::check(
  self : Walk,
  value : Json,
  at : @openapi.Location,
  kind : String,
  dialect : String,
) -> Unit {
  if !self.legacy {
    self.check_bounds(value, at, kind, dialect)
  }
  if self.validator(kind, dialect, at) is Some(validator) {
    for fault in validator.faults(value) {
      if self.violations.length() >= 1000 {
        self.diagnostic(
          "resource.validation-results", "Validation exceeds 1000 reported violations",
          at,
        )
        break
      }
      let location : @openapi.Location = {
        uri: at.uri,
        pointer: at.pointer + fault.at,
      }
      if !self.violations.any(v => {
          v.location == location &&
          v.keyword == fault.keyword &&
          v.schema_pointer == fault.schema_at
        }) {
        self.violations.push({
          keyword: fault.keyword,
          message: fault.message,
          location,
          schema_pointer: fault.schema_at,
        })
      }
    }
  }
}

///|
fn standard_assertions(dialect : String, resources : Map[String, Json]) -> Bool {
  let standard = [
    "https://json-schema.org/draft/2020-12/schema", "https://spec.openapis.org/oas/3.1/dialect/2024-11-10",
  ]
  if standard.contains(dialect) {
    return true
  }
  match resources.get(dialect) {
    Some(Object(fields)) if fields.get("$ref") is Some(String(uri)) =>
      standard.contains(uri)
    _ => false
  }
}

///|
fn Walk::visit(
  self : Walk,
  value : Json,
  at : @openapi.Location,
  kind : String,
  inherited : String,
  depth : Int32,
  target~ : Bool = false,
) -> Unit {
  let dialect = match value {
    Object(fields) if kind == "schema" &&
      fields.get("$schema") is Some(String(uri)) => uri
    _ => inherited
  }
  let key = (at.uri, at.pointer, kind, dialect)
  if self.active.get(key) == Some(true) && kind != "schema" {
    if self.violations.length() < 1000 {
      self.violations.push({
        keyword: "$ref",
        message: "Reference chain has no concrete target",
        location: at,
        schema_pointer: "",
      })
    }
    return
  }
  if self.seen.contains(key) {
    return
  }
  if depth > 128 || self.remaining <= 0 {
    self.diagnostic(
      "resource.validation-graph", "Validation graph exceeds depth 128 or 250000 visited nodes",
      at,
    )
    return
  }
  self.remaining -= 1
  self.seen[key] = true
  self.active[key] = true
  if kind == "schema" && !self.legacy {
    self.check(value, at, kind, dialect)
  }
  if value is Object(fields) {
    if kind == "schema" &&
      self.legacy &&
      fields.get("readOnly") == Some(Json::boolean(true)) &&
      fields.get("writeOnly") == Some(Json::boolean(true)) {
      if self.violations.length() < 1000 {
        self.violations.push({
          keyword: "readOnly/writeOnly",
          message: "OpenAPI 3.0 forbids readOnly and writeOnly together",
          location: at,
          schema_pointer: "",
        })
      } else {
        self.diagnostic(
          "resource.validation-results", "Validation exceeds 1000 reported violations",
          at,
        )
      }
    }
    if self.legacy && kind == "schema" && !fields.contains("$ref") {
      self.check_bounds(value, at, kind, dialect)
    }
    let scoped = kind == "schema" && !self.legacy && fields.contains("$id")
    if scoped {
      self.diagnostic(
        "validation.schema-id",
        "Schema resource $id scopes are not resolved",
        location_key(at, "$id"),
      )
      self.active[key] = false
      return
    }
    if kind == "schema" {
      for keyword in ["$dynamicRef", "$recursiveRef"] {
        if fields.contains(keyword) {
          self.diagnostic(
            "validation.dynamic-reference",
            "Dynamic input reference targets are not resolved",
            location_key(at, keyword),
          )
        }
      }
    }
    if fields.get("$ref") is Some(String(reference)) &&
      [
        "schema", "path-item", "parameter", "header", "response", "request-body",
        "security-scheme", "example", "link", "callback",
      ].contains(kind) {
      match self.resolver.resolve(reference, location_key(at, "$ref")) {
        Err(diagnostic) =>
          self.diagnostic(
            diagnostic.code,
            diagnostic.message,
            diagnostic.location,
          )
        Ok((resolved, location)) => {
          let effective = if location.uri == at.uri {
            dialect
          } else {
            self.target_dialect(location, dialect)
          }
          self.visit(
            resolved,
            location,
            kind,
            effective,
            depth + 1,
            target=true,
          )
        }
      }
      if (kind != "schema" && kind != "path-item") ||
        (kind == "schema" && self.legacy) {
        self.active[key] = false
        return
      }
    } else if target && !(kind == "schema" && !self.legacy) {
      self.check(value, at, kind, dialect)
    }
    let keys = fields.keys().collect()
    keys.sort()
    for name in keys {
      let child = fields[name]
      let child_at = location_key(at, name)
      let next = child_kind(kind, name)
      if next == "" {
        continue
      }
      if next.has_prefix("map:") && child is Object(entries) {
        let keys = entries.keys().collect()
        keys.sort()
        for entry_name in keys {
          if entry_name.has_prefix("x-") &&
            (
              (kind == "root" && name == "paths") ||
              (kind == "operation" && name == "responses")
            ) {
            continue
          }
          self.visit(
            entries[entry_name],
            location_key(child_at, entry_name),
            next[4:].to_owned(),
            dialect,
            depth + 1,
          )
        }
      } else if next.has_prefix("list:") && child is Array(entries) {
        for index, entry in entries {
          self.visit(
            entry,
            location_key(child_at, index.to_string()),
            next[5:].to_owned(),
            dialect,
            depth + 1,
          )
        }
      } else {
        self.visit(child, child_at, next, dialect, depth + 1)
      }
    }
  } else if target && !(kind == "schema" && !self.legacy) {
    self.check(value, at, kind, dialect)
  }
  self.active[key] = false
}

///|
// Walk only specified object positions. Payload examples, enum/const/default
// values, link expressions and extensions can contain ordinary '$ref' keys.
fn child_kind(kind : String, name : String) -> String {
  match (kind, name) {
    ("root", "paths" | "webhooks") => "map:path-item"
    ("root", "components") => "components"
    ("components", "schemas") => "map:schema"
    ("components", "parameters") => "map:parameter"
    ("components", "headers") => "map:header"
    ("components", "responses") => "map:response"
    ("components", "requestBodies") => "map:request-body"
    ("components", "securitySchemes") => "map:security-scheme"
    ("components", "examples") => "map:example"
    ("components", "links") => "map:link"
    ("components", "callbacks") => "map:callback"
    ("components", "pathItems") => "map:path-item"
    (
      "path-item",
      "get"
      | "put"
      | "post"
      | "delete"
      | "options"
      | "head"
      | "patch"
      | "trace",
    ) => "operation"
    ("path-item" | "operation", "parameters") => "list:parameter"
    ("operation", "requestBody") => "request-body"
    ("operation", "responses") => "map:response"
    ("operation", "callbacks") => "map:callback"
    ("callback", _) =>
      if name == "$ref" || name.has_prefix("x-") {
        ""
      } else {
        "path-item"
      }
    ("parameter" | "header" | "media", "schema") => "schema"
    ("parameter" | "header" | "media", "examples") => "map:example"
    ("request-body" | "response" | "parameter" | "header", "content") =>
      "map:media"
    ("response" | "encoding", "headers") => "map:header"
    ("response", "links") => "map:link"
    ("media", "encoding") => "map:encoding"
    (
      "schema",
      "properties"
      | "patternProperties"
      | "$defs"
      | "definitions"
      | "dependentSchemas",
    ) => "map:schema"
    ("schema", "allOf" | "anyOf" | "oneOf" | "prefixItems") => "list:schema"
    (
      "schema",
      "items"
      | "additionalProperties"
      | "not"
      | "contains"
      | "if"
      | "then"
      | "else"
      | "propertyNames"
      | "unevaluatedProperties"
      | "unevaluatedItems",
    ) => "schema"
    _ => ""
  }
}
