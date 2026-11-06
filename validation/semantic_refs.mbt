///|
priv struct SemanticContext {
  resolver : @openapi.ReferenceResolver
  violations : Array[Violation]
  diagnostics : Array[@openapi.Diagnostic]
  mut remaining : Int32
}

///|
fn SemanticContext::spend(
  self : SemanticContext,
  at : @openapi.Location,
) -> Bool {
  if self.violations.length() > 1000 || self.diagnostics.length() >= 1000 {
    return false
  }
  if self.remaining <= 0 {
    if !self.diagnostics.any(d => d.code == "resource.validation-semantics") {
      self.diagnostics.push({
        code: "resource.validation-semantics",
        message: "Cross-object validation exceeds 250000 visits",
        location: at,
      })
    }
    return false
  }
  self.remaining -= 1
  true
}

///|
fn SemanticContext::target(
  self : SemanticContext,
  value : Json,
  at : @openapi.Location,
  path_item~ : Bool = false,
) -> (Map[String, Json], @openapi.Location)? {
  let mut current = value
  let mut origin = at
  let seen = Map([])
  for _ in 0..<128 {
    if !self.spend(origin) {
      return None
    }
    if seen.contains((origin.uri, origin.pointer)) {
      return None
    }
    seen[(origin.uri, origin.pointer)] = true
    guard current is Object(fields) else { return None }
    match fields.get("$ref") {
      None => return Some((fields, origin))
      Some(String(reference)) => {
        if path_item &&
          fields
          .keys()
          .any(name => {
            name != "$ref" &&
            name != "summary" &&
            name != "description" &&
            !name.has_prefix("x-")
          }) {
          self.diagnostics.push({
            code: "validation.path-item-sibling",
            message: "Path Item reference with concrete siblings needs an explicit merge policy",
            location: origin,
          })
          return None
        }
        match self.resolver.resolve(reference, location_key(origin, "$ref")) {
          Ok((target, location)) => {
            current = target
            origin = location
          }
          // The typed reference walk reports missing, malformed and cyclic
          // targets before this cross-object pass.
          Err(_) => return None
        }
      }
      _ => return None
    }
  }
  None
}
