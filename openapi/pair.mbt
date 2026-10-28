///|
/// Parse independent snapshots, resolving only identities required by their
/// common operations before finalizing conflicts and public documents.
pub fn parse_pair(
  before : SourceDocument,
  after : SourceDocument,
  before_load~ : ((String, String) -> SourceDocument raise DocumentError)? = None,
  after_load~ : ((String, String) -> SourceDocument raise DocumentError)? = None,
  before_document_url~ : String? = None,
  after_document_url~ : String? = None,
) -> DocumentPair raise PairError {
  let baseline = prepare_entry(
    before.text,
    format=before.format,
    source=before.source,
    load=before_load,
    document_url=before_document_url,
  ) catch {
    error => raise Before(error)
  }
  let candidate = prepare_entry(
    after.text,
    format=after.format,
    source=after.source,
    load=after_load,
    document_url=after_document_url,
  ) catch {
    error => raise After(error)
  }
  let candidate_indices : Map[(String, String), Int32] = Map([])
  for index, operation in candidate.operations {
    candidate_indices[(operation.http_method, operation.path)] = index
  }
  for index, old in baseline.operations {
    if candidate_indices.get((old.http_method, old.path)) is Some(other) {
      let next = candidate.operations[other]
      baseline.context.graph.propagate_origin_conflicts()
      candidate.context.graph.propagate_origin_conflicts()
      if !baseline.context.operation_ready(old) ||
        !candidate.context.operation_ready(next) {
        continue
      }
      let required : Map[String, Bool] = Map([])
      for name in old.schemes {
        required[name] = true
      }
      for name in next.schemes {
        required[name] = true
      }
      let names = sorted_keys(required)
      baseline.operations[index] = baseline.context.supplement_operation(
        old,
        names,
        baseline.diagnostics,
      )
      baseline.context.graph.propagate_origin_conflicts()
      if baseline.context.operation_ready(baseline.operations[index]) {
        candidate.operations[other] = candidate.context.supplement_operation(
          next,
          names,
          candidate.diagnostics,
        )
      }
    }
  }
  { before: finalize_entry(baseline), after: finalize_entry(candidate), }
}

///|
fn Context::supplement_operation(
  self : Context,
  operation : Operation,
  names : Array[String],
  diagnostics : Array[Diagnostic],
) -> Operation {
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
  for name in names {
    self.graph.propagate_origin_conflicts()
    if !self.operation_ready(operation) {
      break
    }
    if present.contains(name) || !self.declared.contains(name) {
      continue
    }
    try {
      // Failed attempts also consume one existing used-work unit; successful
      // expansion charges only its remaining variants inside identity().
      self.charge_identity_tuples(1, true, operation.security_location)
      let identity = self.identity(
        name,
        selection,
        used=true,
        external=true,
        prepaid=true,
        operation=Some((operation.http_method, operation.path)),
      )
      identities.push(identity)
      present[name] = true
    } catch {
      AuthError(code, message, location) => {
        diagnostics.push({
          code,
          message: "Peer-required scheme '" + name + "': " + message,
          location,
        })
        if code == "resource.identities" {
          break
        }
      }
    }
  }
  { ..operation, scheme_identities: identities, }
}
