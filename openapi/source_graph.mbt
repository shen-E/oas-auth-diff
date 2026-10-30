///|
fn source_graph(
  input : SourceDocument,
  root : Value,
  nodes : Int32,
  load : ((String, String) -> SourceDocument raise DocumentError)?,
  document_url : String?,
  explicit_urls~ : Bool = false,
) -> Graph {
  let graph : Graph = {
    documents: Map([]),
    requests: Map([]),
    load,
    resource_diagnostics: [],
    explicit_urls,
    conflicted_origins: Map([]),
    conflicted_contents: Map([]),
    origin_children: Map([]),
    bytes: @utf8.encode(input.text).length(),
    nodes,
    operations: 0,
    atoms: 0,
  }
  graph.documents[input.source] = { input, value: Ok(root), document_url, }
  graph
}
