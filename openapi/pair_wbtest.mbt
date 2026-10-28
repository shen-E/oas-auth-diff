///|
fn pair_test_live(
  load : (String, String) -> SourceDocument raise DocumentError,
) -> LiveDocument raise DocumentError {
  let root : Json = {
    "openapi": "3.1.1",
    "components": {
      "securitySchemes": {
        "A": { "type": "http", "scheme": "basic" },
        "B": { "$ref": "b.yaml#/B" },
        "C": { "$ref": "c.yaml#/B" },
      },
    },
    "paths": { "/data": { "get": { "security": [{ "A": [] }] } } },
  }
  prepare_entry(
    root.stringify(),
    format=Json,
    source="file:///entry.json",
    load=Some(load),
    document_url=None,
  )
}

///|
test "peer-required loading never borrows a false-mode failure or rereads successful sources" {
  let calls : Array[String] = []
  let live = pair_test_live((_, path) => {
    calls.push(path)
    {
      text: "B: {type: http, scheme: bearer}",
      format: Yaml,
      source: "file:///b.yaml",
    }
  })
  ignore(live.context.scheme("B", external=false)) catch {
    _ => ()
  }
  assert_eq(calls.length(), 0)
  let first = live.context.supplement_operation(
    live.operations[0],
    ["A", "B"],
    live.diagnostics,
  )
  let nodes = live.context.graph.nodes
  let documents = live.context.graph.documents.length()
  let second = live.context.supplement_operation(
    live.operations[0],
    ["B"],
    live.diagnostics,
  )
  assert_eq(calls.length(), 1)
  assert_eq(live.context.graph.nodes, nodes)
  assert_eq(live.context.graph.documents.length(), documents)
  assert_eq(first.scheme_identities.length(), 2)
  assert_eq(second.scheme_identities.length(), 2)
  assert_eq(live.context.used_identities, 3)
  assert_eq(live.diagnostics.length(), 0)
}

///|
test "peer-required work precharges failed attempts and refuses IO when exhausted" {
  let calls : Array[String] = []
  let live = pair_test_live((_, path) => {
    calls.push(path)
    raise DocumentError("source unavailable")
  })
  let _ = live.context.supplement_operation(
    live.operations[0],
    ["B"],
    live.diagnostics,
  )
  let _ = live.context.supplement_operation(
    live.operations[0],
    ["B"],
    live.diagnostics,
  )
  assert_eq(calls.length(), 1)
  assert_eq(live.context.used_identities, 3)
  assert_eq(live.diagnostics.length(), 2)
  assert_eq(live.diagnostics[0].code, "ref.load")
  live.context.used_identities = 100000
  let _ = live.context.supplement_operation(
    live.operations[0],
    ["B", "C"],
    live.diagnostics,
  )
  assert_eq(calls.length(), 1)
  assert_eq(live.context.used_identities, 100000)
  assert_eq(live.diagnostics[2].code, "resource.identities")
  assert_eq(live.diagnostics.length(), 3)
  assert_true(live.operations[0].policy is Some(_))
}

///|
test "content-poisoned cached definitions are excluded from public snapshots" {
  let live = pair_test_live((_, path) => {
    text: if path == "b.yaml" {
      "B: {type: http, scheme: bearer}"
    } else {
      "B: {type: http, scheme: basic}"
    },
    format: Yaml,
    source: "file:///b.yaml",
  })
  ignore(live.context.scheme("B"))
  ignore(live.context.scheme("C")) catch {
    error => live.diagnostics.push(diagnostic(error))
  }
  let document = finalize_entry(live)
  assert_true(document.diagnostics.any(item => item.code == "ref.conflict"))
  assert_eq(document.schemes.length(), 1)
  assert_eq(document.schemes[0].name, "A")
  assert_true(document.operations[0].policy is Some(_))
  assert_eq(document.operations[0].scheme_identities.length(), 1)
}
