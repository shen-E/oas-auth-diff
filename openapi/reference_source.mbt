///|
/// A strict JSON/YAML source graph with caller-controlled loading and shared
/// reference budgets. It does not interpret OpenAPI or JSON Schema assertions.
pub struct ReferenceResolver {
  priv graph : Graph
  source : String
}

///|
pub fn ReferenceResolver::new(
  input : SourceDocument,
  load~ : ((String, String) -> SourceDocument raise DocumentError)? = None,
) -> ReferenceResolver raise DocumentError {
  let (root, nodes) = read_input(input.text, input.format)
  { graph: source_graph(input, root, nodes, load, None), source: input.source, }
}

///|
pub fn ReferenceResolver::root(self : ReferenceResolver) -> Json {
  match self.graph.documents[self.source].value {
    Ok(value) => value_json(value)
    Err(_) => abort("entry source was parsed before constructing the resolver")
  }
}

///|
/// Resolve a URI reference relative to a location previously returned by this
/// resolver. Returned JSON is an independent snapshot of the cached source.
pub fn ReferenceResolver::resolve(
  self : ReferenceResolver,
  reference : String,
  at : Location,
) -> Result[(Json, Location), Diagnostic] {
  if !self.graph.documents.contains(at.uri) {
    return Err({
      code: "ref.source",
      message: "Unknown referring source",
      location: at,
    })
  }
  try {
    let (value, location) = self.graph.lookup_ref(reference, at)
    Ok((value_json(value), location))
  } catch {
    AuthError(code, message, location) => Err({ code, message, location, })
  }
}
