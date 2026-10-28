///|
fn pair_schemes(b~ : Json = { "$ref": "auth/b.json" }) -> Json {
  {
    "A": { "type": "apiKey", "in": "header", "name": "X-A" },
    "B": b,
    "Relative": {
      "type": "oauth2",
      "flows": {
        "clientCredentials": {
          "tokenUrl": "token",
          "scopes": { "read": "Read", "write": "Write" },
        },
      },
    },
    "Absolute": {
      "type": "oauth2",
      "flows": {
        "clientCredentials": {
          "tokenUrl": "https://identity.example/token",
          "scopes": { "read": "Read", "write": "Write" },
        },
      },
    },
  }
}

///|
fn pair_spec(paths : Json, schemes~ : Json = pair_schemes()) -> String {
  let root : Json = {
    "openapi": "3.1.1",
    "servers": [{ "url": "https://api.example/v1/" }],
    "components": { "securitySchemes": schemes },
    "paths": paths,
  }
  root.stringify()
}

///|
fn pair_source(text : String, before~ : Bool) -> @openapi.SourceDocument {
  {
    text,
    format: @openapi.Json,
    source: if before {
      "file:///before/openapi.json"
    } else {
      "file:///after/openapi.json"
    },
  }
}

///|
fn pair_b_definition(name~ : String = "X-B") -> @openapi.SourceDocument {
  let value : Json = { "type": "apiKey", "in": "header", "name": name }
  {
    text: value.stringify(),
    format: @openapi.Json,
    source: "file:///shared/b.json",
  }
}

///|
fn pair_loader(
  sources : Map[String, @openapi.SourceDocument],
  calls : Array[String],
) -> (String, String) -> @openapi.SourceDocument raise @openapi.DocumentError {
  (from, path) => {
    let key = from + "|" + path
    calls.push(key)
    match sources.get(key) {
      Some(source) => source
      None => raise @openapi.DocumentError("No supplied source: " + key)
    }
  }
}

///|
fn paired_documents(
  before : String,
  after : String,
  before_sources : Map[String, @openapi.SourceDocument],
  after_sources : Map[String, @openapi.SourceDocument],
  before_calls : Array[String],
  after_calls : Array[String],
  document_url~ : String? = None,
) -> @openapi.DocumentPair raise @openapi.PairError {
  @openapi.parse_pair(
    pair_source(before, before=true),
    pair_source(after, before=false),
    before_load=Some(pair_loader(before_sources, before_calls)),
    after_load=Some(pair_loader(after_sources, after_calls)),
    before_document_url=document_url,
    after_document_url=document_url,
  )
}

///|
test "paired preparation proves removed external requirements without making compare perform IO" {
  let before = pair_spec({
    "/data": { "get": { "security": [{ "A": [], "B": [] }] } },
  })
  let after = pair_spec({ "/data": { "get": { "security": [{ "A": [] }] } } })
  let old_sources = {
    "file:///before/openapi.json|auth/b.json": pair_b_definition(),
  }
  let new_sources = {
    "file:///after/openapi.json|auth/b.json": pair_b_definition(),
  }
  let old_control_calls = []
  let new_control_calls = []
  let old_control = @openapi.parse_with_loader(
    before,
    format=@openapi.Json,
    source="file:///before/openapi.json",
    load=pair_loader(old_sources, old_control_calls),
  )
  let new_control = @openapi.parse_with_loader(
    after,
    format=@openapi.Json,
    source="file:///after/openapi.json",
    load=pair_loader(new_sources, new_control_calls),
  )
  assert_eq(@diff.compare(old_control, new_control).exit_code(), 2)
  assert_eq(old_control_calls.length(), 1)
  assert_true(new_control_calls.is_empty())
  let old_calls = []
  let new_calls = []
  let prepared = paired_documents(
    before, after, old_sources, new_sources, old_calls, new_calls,
  )
  assert_eq(old_calls.length(), 1)
  assert_eq(new_calls.length(), 1)
  let result = @diff.compare(prepared.before, prepared.after)
  assert_eq(result.exit_code(), 1)
  assert_eq(result.changes[0].kind, @diff.Weakened)
  let witness = result.changes[0].witness.unwrap()
  assert_true(witness.atoms().contains(@logic.Credential("A")))
  assert_false(witness.atoms().contains(@logic.Credential("B")))
  assert_true(result.changes[0].after.unwrap().allows(witness))
  assert_false(result.changes[0].before.unwrap().allows(witness))
  ignore(@diff.render_json(@diff.compare(prepared.before, prepared.after)))
  assert_eq(old_calls.length(), 1)
  assert_eq(new_calls.length(), 1)
}

///|
test "pair loading is limited to each common method and path's used names" {
  let declarations : Json = {
    "A": { "type": "apiKey", "in": "header", "name": "X-A" },
    "B": { "$ref": "auth/b.json" },
    "Added": { "$ref": "auth/added.json" },
    "Removed": { "$ref": "auth/removed.json" },
    "Unused": { "$ref": "auth/unused.json" },
  }
  let before = pair_spec(
    {
      "/common": { "get": { "security": [{ "A": [], "B": [] }] } },
      "/old": { "get": { "security": [{ "Removed": [] }] } },
    },
    schemes=declarations,
  )
  let after = pair_spec(
    {
      "/common": { "get": { "security": [{ "A": [] }] } },
      "/new": { "post": { "security": [{ "Added": [] }] } },
    },
    schemes=declarations,
  )
  let old_calls = []
  let new_calls = []
  let prepared = paired_documents(
    before,
    after,
    {
      "file:///before/openapi.json|auth/b.json": pair_b_definition(),
      "file:///before/openapi.json|auth/removed.json": {
        ..pair_b_definition(name="X-Removed"),
        source: "file:///shared/removed.json",
      },
    },
    {
      "file:///after/openapi.json|auth/b.json": pair_b_definition(),
      "file:///after/openapi.json|auth/added.json": {
        ..pair_b_definition(name="X-Added"),
        source: "file:///shared/added.json",
      },
    },
    old_calls,
    new_calls,
  )
  assert_eq(@diff.compare(prepared.before, prepared.after).exit_code(), 1)
  assert_eq(old_calls.length(), 2)
  assert_eq(new_calls.length(), 2)
  assert_false(
    old_calls.any(call => {
      call.contains("added.json") || call.contains("unused.json")
    }),
  )
  assert_false(
    new_calls.any(call => {
      call.contains("removed.json") || call.contains("unused.json")
    }),
  )
  let method_old = pair_spec({
    "/method": { "get": { "security": [{ "A": [], "B": [] }] } },
  })
  let method_new = pair_spec({
    "/method": { "post": { "security": [{ "A": [] }] } },
  })
  let old_method_calls = []
  let new_method_calls = []
  let methods = paired_documents(
    method_old,
    method_new,
    { "file:///before/openapi.json|auth/b.json": pair_b_definition() },
    {},
    old_method_calls,
    new_method_calls,
  )
  assert_eq(@diff.compare(methods.before, methods.after).exit_code(), 0)
  assert_eq(old_method_calls.length(), 1)
  assert_true(new_method_calls.is_empty())
}

///|
test "pair failures remain cached and fatal errors retain their input side" {
  let before = pair_spec({
    "/one": { "get": { "security": [{ "A": [], "B": [] }] } },
    "/two": { "get": { "security": [{ "A": [], "B": [] }] } },
    "/valid": { "get": { "security": [{ "A": ["admin"] }] } },
  })
  let after = pair_spec({
    "/one": { "get": { "security": [{ "A": [] }] } },
    "/two": { "get": { "security": [{ "A": [] }] } },
    "/valid": { "get": { "security": [{ "A": [] }] } },
  })
  for malformed in [false, true] {
    let new_calls = []
    let prepared = @openapi.parse_pair(
      pair_source(before, before=true),
      pair_source(after, before=false),
      before_load=Some(
        pair_loader(
          { "file:///before/openapi.json|auth/b.json": pair_b_definition() },
          [],
        ),
      ),
      after_load=Some((from, path) => {
        new_calls.push(from + "|" + path)
        if new_calls.length() == 1 {
          if malformed {
            @openapi.SourceDocument::{ ..pair_b_definition(), text: "{", }
          } else {
            raise @openapi.DocumentError("Temporary load failure")
          }
        } else {
          pair_b_definition()
        }
      }),
    )
    assert_eq(new_calls.length(), 1)
    let result = @diff.compare(prepared.before, prepared.after)
    assert_eq(result.exit_code(), 2)
    let valid = result.changes
      .iter()
      .find_first(change => change.path == "/valid")
      .unwrap()
    assert_eq(valid.kind, @diff.Weakened)
    assert_true(valid.witness is Some(_))
  }
  try
    @openapi.parse_pair(
      pair_source("{", before=true),
      pair_source(after, before=false),
    )
  catch {
    @openapi.Before(_) => ()
    _ => fail("expected a baseline parse error")
  } noraise {
    _ => fail("expected the baseline input to fail")
  }
  try
    @openapi.parse_pair(
      pair_source(after, before=true),
      pair_source("{", before=false),
    )
  catch {
    @openapi.After(_) => ()
    _ => fail("expected a candidate parse error")
  } noraise {
    _ => fail("expected the candidate input to fail")
  }
}

///|
test "identical canonical source names do not merge before and after snapshots" {
  let before = pair_spec({
    "/data": { "get": { "security": [{ "A": [], "B": [] }] } },
  })
  let after = pair_spec({ "/data": { "get": { "security": [{ "A": [] }] } } })
  let prepared = paired_documents(
    before,
    after,
    { "file:///before/openapi.json|auth/b.json": pair_b_definition() },
    {
      "file:///after/openapi.json|auth/b.json": pair_b_definition(
        name="X-New-B",
      ),
    },
    [],
    [],
  )
  assert_false(
    prepared.before.diagnostics.any(issue => issue.code == "ref.conflict"),
  )
  assert_false(
    prepared.after.diagnostics.any(issue => issue.code == "ref.conflict"),
  )
  let result = @diff.compare(prepared.before, prepared.after)
  assert_eq(result.exit_code(), 2)
  assert_eq(result.changes[0].kind, @diff.Incomparable)
  assert_true(
    result.diagnostics.any(issue => issue.code == "scheme-incomparable"),
  )
}

///|
test "needed identity loading can invalidate an earlier deployment origin without losing absolute findings" {
  let before = pair_spec(
    {
      "/a-shared": { "$ref": "public/shared.json#/item" },
      "/pair": { "get": { "security": [{ "A": [], "B": [] }] } },
    },
    schemes=pair_schemes(b={ "type": "apiKey", "in": "header", "name": "X-B" }),
  )
  let after = pair_spec(
    {
      "/a-shared": { "$ref": "public/shared.json#/item" },
      "/pair": { "get": { "security": [{ "A": [] }] } },
    },
    schemes=pair_schemes(b={ "$ref": "private/shared.json#/B" }),
  )
  let shared =
    #|{"B":{"type":"apiKey","in":"header","name":"X-B"},"item":{"servers":[{"url":"api/"}],"get":{"security":[{"Relative":["read","write"]}]},"post":{"servers":[{"url":"https://stable.example/api/"}],"security":[{"Relative":["read","write"]}]},"put":{"security":[{"Absolute":["read","write"]}]}}}
  let changed = shared.replace_all(old="[\"read\",\"write\"]", new="[\"read\"]")
  let prepared = paired_documents(
    before,
    after,
    {
      "file:///before/openapi.json|public/shared.json": {
        source: "file:///shared.json",
        format: @openapi.Json,
        text: shared,
      },
    },
    {
      "file:///after/openapi.json|public/shared.json": {
        source: "file:///shared.json",
        format: @openapi.Json,
        text: changed,
      },
      "file:///after/openapi.json|private/shared.json": {
        source: "file:///shared.json",
        format: @openapi.Json,
        text: changed,
      },
    },
    [],
    [],
    document_url=Some("https://docs.example/root/openapi.json"),
  )
  let result = @diff.compare(prepared.before, prepared.after)
  assert_eq(result.exit_code(), 2)
  assert_true(result.diagnostics.any(issue => issue.code == "ref.conflict"))
  for change in result.changes {
    if change.path == "/a-shared" {
      if change.http_method == "GET" {
        assert_eq(change.kind, @diff.Incomparable)
        assert_true(change.witness is None)
        assert_true(change.after is None)
      } else {
        assert_eq(change.kind, @diff.Weakened)
        assert_true(change.witness is Some(_))
      }
    }
  }
  assert_eq(
    result.changes.filter(change => change.path == "/a-shared").length(),
    3,
  )
}

///|
test "late content conflicts follow exact path chains even when they share an anonymous target" {
  let paths_before : Json = {
    "/a-path": { "$ref": "clean/parent.json#/item" },
    "/b-path": { "$ref": "other/parent.json#/item" },
    "/pair": { "get": { "security": [{ "A": [], "B": [] }] } },
  }
  let paths_after : Json = {
    "/a-path": { "$ref": "clean/parent.json#/item" },
    "/b-path": { "$ref": "other/parent.json#/item" },
    "/pair": { "get": { "security": [{ "A": [] }] } },
  }
  let before = pair_spec(
    paths_before,
    schemes=pair_schemes(b={ "type": "apiKey", "in": "header", "name": "X-B" }),
  )
  let after = pair_spec(
    paths_after,
    schemes=pair_schemes(b={ "$ref": "mutated-parent.json#/B" }),
  )
  let parent_text = "{\"item\":{\"$ref\":\"../target.json#/item\"}}"
  let old_target = "{\"item\":{\"get\":{\"security\":[{\"Absolute\":[\"read\",\"write\"]}]}}}"
  let new_target = "{\"item\":{\"get\":{\"security\":[]}}}"
  let old_sources : Map[String, @openapi.SourceDocument] = {
    "file:///before/openapi.json|clean/parent.json": {
      source: "file:///shared/clean.json",
      format: @openapi.Json,
      text: parent_text,
    },
    "file:///before/openapi.json|other/parent.json": {
      source: "file:///shared/other.json",
      format: @openapi.Json,
      text: parent_text,
    },
    "file:///shared/clean.json|../target.json": {
      source: "file:///shared/target.json",
      format: @openapi.Json,
      text: old_target,
    },
    "file:///shared/other.json|../target.json": {
      source: "file:///shared/target.json",
      format: @openapi.Json,
      text: old_target,
    },
  }
  let new_sources : Map[String, @openapi.SourceDocument] = {
    "file:///after/openapi.json|clean/parent.json": {
      source: "file:///shared/clean.json",
      format: @openapi.Json,
      text: parent_text,
    },
    "file:///after/openapi.json|other/parent.json": {
      source: "file:///shared/other.json",
      format: @openapi.Json,
      text: parent_text,
    },
    "file:///shared/clean.json|../target.json": {
      source: "file:///shared/target.json",
      format: @openapi.Json,
      text: new_target,
    },
    "file:///shared/other.json|../target.json": {
      source: "file:///shared/target.json",
      format: @openapi.Json,
      text: new_target,
    },
    "file:///after/openapi.json|mutated-parent.json": {
      source: "file:///shared/clean.json",
      format: @openapi.Json,
      text: "{\"B\":{\"type\":\"apiKey\",\"in\":\"header\",\"name\":\"X-B\"}}",
    },
  }
  let prepared = paired_documents(before, after, old_sources, new_sources, [], [])
  let result = @diff.compare(prepared.before, prepared.after)
  assert_eq(result.exit_code(), 2)
  assert_true(result.diagnostics.any(issue => issue.code == "ref.conflict"))
  let dependent = result.changes
    .iter()
    .find_first(change => change.path == "/a-path")
    .unwrap()
  assert_eq(dependent.kind, @diff.Incomparable)
  assert_true(dependent.after is None)
  assert_true(dependent.witness is None)
  let independent = result.changes
    .iter()
    .find_first(change => change.path == "/b-path")
    .unwrap()
  assert_eq(independent.kind, @diff.Weakened)
  assert_true(independent.witness.unwrap().atoms().is_empty())
  assert_true(independent.after.unwrap().allows(@logic.GrantSet::new([])))
  assert_false(independent.before.unwrap().allows(@logic.GrantSet::new([])))
}

///|
test "supplemented external identities retain each operation's own server context" {
  let before = pair_spec({
    "/one": {
      "get": {
        "servers": [{ "url": "https://one.example/api/" }],
        "security": [{ "A": [], "B": ["read"] }],
      },
    },
    "/two": {
      "get": {
        "servers": [{ "url": "https://two.example/api/" }],
        "security": [{ "A": [], "B": ["read"] }],
      },
    },
  })
  let after = pair_spec({
    "/one": {
      "get": {
        "servers": [{ "url": "https://one.example/api/" }],
        "security": [{ "A": [] }],
      },
    },
    "/two": {
      "get": {
        "servers": [{ "url": "https://changed.example/api/" }],
        "security": [{ "A": [] }],
      },
    },
  })
  let b : @openapi.SourceDocument = {
    source: "file:///shared/b.json",
    format: @openapi.Json,
    text: "{\"$ref\":\"defs/oauth.json\"}",
  }
  let target : @openapi.SourceDocument = {
    source: "file:///shared/defs/oauth.json",
    format: @openapi.Json,
    text: "{\"type\":\"oauth2\",\"flows\":{\"clientCredentials\":{\"tokenUrl\":\"token\",\"scopes\":{\"read\":\"Read\"}}}}",
  }
  let old_calls = []
  let new_calls = []
  let prepared = paired_documents(
    before,
    after,
    {
      "file:///before/openapi.json|auth/b.json": b,
      "file:///shared/b.json|defs/oauth.json": target,
    },
    {
      "file:///after/openapi.json|auth/b.json": b,
      "file:///shared/b.json|defs/oauth.json": target,
    },
    old_calls,
    new_calls,
  )
  assert_eq(old_calls.length(), 2)
  assert_eq(new_calls.length(), 2)
  let result = @diff.compare(prepared.before, prepared.after)
  assert_eq(result.exit_code(), 2)
  let one = result.changes
    .iter()
    .find_first(change => change.path == "/one")
    .unwrap()
  let two = result.changes
    .iter()
    .find_first(change => change.path == "/two")
    .unwrap()
  assert_eq(one.kind, @diff.Weakened)
  assert_true(one.witness is Some(_))
  assert_eq(two.kind, @diff.Incomparable)
  assert_true(two.witness is None)
}

///|
test "pair supplementation shares the entry document budget with initial path loading" {
  let before = pair_spec(
    { "/pair": { "get": { "security": [{ "A": [], "B": [] }] } } },
    schemes=pair_schemes(b={ "type": "apiKey", "in": "header", "name": "X-B" }),
  )
  let paths : Map[String, Json] = {
    "/pair": { "get": { "security": [{ "A": [] }] } },
  }
  let sources : Map[String, @openapi.SourceDocument] = Map([])
  for index in 0..<63 {
    let file = "part-" + index.to_string() + ".json"
    paths["/part-" + index.to_string()] = { "$ref": file }
    sources["file:///after/openapi.json|" + file] = {
      source: "file:///after/" + file,
      format: @openapi.Json,
      text: "{\"get\":{\"security\":[{\"A\":[]}]}}",
    }
  }
  sources["file:///after/openapi.json|auth/b.json"] = pair_b_definition()
  let calls = []
  let prepared = paired_documents(
    before,
    pair_spec(Json::object(paths)),
    {},
    sources,
    [],
    calls,
  )
  assert_eq(calls.length(), 63)
  assert_false(calls.any(call => call.contains("auth/b.json")))
  assert_true(
    prepared.after.diagnostics.any(issue => issue.code == "resource.documents"),
  )
  let result = @diff.compare(prepared.before, prepared.after)
  assert_eq(result.exit_code(), 2)
  let affected = result.changes
    .iter()
    .find_first(change => change.path == "/pair")
    .unwrap()
  assert_eq(affected.kind, @diff.Incomparable)
  assert_true(affected.witness is None)
}
