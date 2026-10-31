///|
priv struct SchemaIndex {
  anchors : Map[String, Result[(Value, Location), Diagnostic]]
}

///|
fn anchor_name(name : String) -> Bool {
  let chars = name.to_array()
  !chars.is_empty() &&
  (url_alpha(chars[0]) || chars[0] == '_') &&
  chars.all(c => {
    url_alpha(c) || url_digit(c) || c == '_' || c == '-' || c == '.'
  })
}

///|
// Only Schema positions introduce identifiers. Example/default/enum and
// extension payloads are data even when they contain identifier-looking keys.
fn anchor_child(kind : String, name : String) -> String {
  match (kind, name) {
    ("root", "paths" | "webhooks") => "map:path-item"
    ("root", "components") => "components"
    ("components", "schemas") => "map:schema"
    ("components", "parameters") => "map:parameter"
    ("components", "headers") => "map:header"
    ("components", "responses") => "map:response"
    ("components", "requestBodies") => "map:request-body"
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
    ("request-body" | "response" | "parameter" | "header", "content") =>
      "map:media"
    ("response" | "encoding", "headers") => "map:header"
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
      | "additionalItems"
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

///|
fn Graph::schema_index(self : Graph, uri : String) -> SchemaIndex {
  if self.schema_indexes.get(uri) is Some(index) {
    return index
  }
  let index : SchemaIndex = { anchors: Map([]), }
  let root = match self.documents[uri].value {
    Ok(root) => root
    Err(_) => return index
  }
  let kind = match root {
    Obj(fields) if fields.contains("openapi") => "root"
    _ => "schema"
  }
  let stack : Array[(Value, Location, String, Bool)] = [
    (root, { uri, pointer: "", }, kind, false),
  ]
  while stack.pop() is Some((value, at, kind, parent_scoped)) {
    guard value is Obj(fields) else { continue }
    let scoped = parent_scoped || (kind == "schema" && fields.contains("$id"))
    if kind == "schema" {
      if !scoped {
        for keyword in ["$anchor", "$dynamicAnchor"] {
          if fields.get(keyword) is Some(Str(name)) && anchor_name(name) {
            index.anchors[name] = if index.anchors.contains(name) {
              Err({
                code: "ref.anchor-ambiguous",
                message: "Duplicate Schema anchor in the same resource: " + name,
                location: at.key(keyword),
              })
            } else {
              Ok((value, at))
            }
          }
        }
      }
    }
    for name in sorted_keys(fields) {
      if name.has_prefix("x-") && kind != "schema" {
        continue
      }
      let child = fields[name]
      let child_at = at.key(name)
      let next = anchor_child(kind, name)
      if next.has_prefix("map:") && child is Obj(entries) {
        for entry in sorted_keys(entries) {
          if entry.has_prefix("x-") &&
            (
              (kind == "root" && name == "paths") ||
              (kind == "operation" && name == "responses")
            ) {
            continue
          }
          stack.push(
            (entries[entry], child_at.key(entry), next[4:].to_owned(), scoped),
          )
        }
      } else if next.has_prefix("list:") && child is Seq(entries) {
        for n, entry in entries {
          stack.push(
            (entry, child_at.key(n.to_string()), next[5:].to_owned(), scoped),
          )
        }
      } else if next != "" {
        stack.push((child, child_at, next, scoped))
      }
    }
  }
  // The index visits only already bounded source nodes and never follows refs.
  self.schema_indexes[uri] = index
  index
}

///|
fn Graph::schema_scope(self : Graph, at : Location) -> Unit raise AuthError {
  let mut value = self.lookup_ref("#", at).0
  let parts = at.pointer.split("/").drop(1).collect()
  for index in 0..<=parts.length() {
    if value is Obj(fields) && fields.contains("$id") {
      issue("ref.schema-id", "Schema $id resource scopes are not resolved", at)
    }
    if index == parts.length() {
      break
    }
    let key = decode_segment(parts[index].to_owned(), at)
    match value {
      Obj(fields) =>
        match fields.get(key) {
          Some(child) => value = child
          None => break
        }
      Seq(items) =>
        match items.get(array_index(key, at)) {
          Some(child) => value = child
          None => break
        }
      _ => break
    }
  }
}

///|
fn Graph::lookup_schema_ref(
  self : Graph,
  reference : String,
  at : Location,
) -> (Value, Location) raise AuthError {
  self.schema_scope(at)
  let result = self.lookup_ref(reference, at, schema=true)
  self.schema_scope(result.1)
  result
}
