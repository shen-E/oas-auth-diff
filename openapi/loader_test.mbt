///|
fn entry_refs(references : Array[String]) -> String {
  let paths = references.mapi((index, reference) => {
    Json::string("/ref" + index.to_string()).stringify() +
    ":{\"$ref\":" +
    Json::string(reference).stringify() +
    "}"
  })
  "{\"openapi\":\"3.1.1\",\"paths\":{\"/ok\":{\"get\":{}}," +
  paths.join(",") +
  "}}"
}

///|
test "loader path validation occurs before callbacks and allows decoded file names" {
  for
    reference in [
      "/absolute.yaml", "//server/file.yaml", "https://example.test/file.yaml", "file:///root/file.yaml",
      "C:/file.yaml", "a\\file.yaml", "file.yaml?query", "%2Fabsolute.yaml", "%2f%2fserver/file.yaml",
      "a%3Afile.yaml", "a%5Cfile.yaml", "%00file.yaml", "a%0Afile.yaml", "bad%QQ.yaml",
      "bad%.yaml", "raw space.yaml",
    ] {
    let calls : Array[String] = []
    let document = @openapi.parse_with_loader(
      entry_refs([reference]),
      format=@openapi.Json,
      source="file:///entry.json",
      load=(_, path) => {
        calls.push(path)
        {
          text: "{\"get\":{}}",
          format: @openapi.Json,
          source: "file:///part.json",
        }
      },
    )
    assert_eq(calls.length(), 0)
    assert_eq(document.diagnostics[0].code, "ref.path")
    assert_eq(document.operations.length(), 1)
  }
  let calls : Array[String] = []
  let accepted = @openapi.parse_with_loader(
    entry_refs(["parts/auth%20file.yaml#", "../other%23file.yaml"]),
    format=@openapi.Json,
    source="file:///entry.json",
    load=(_, path) => {
      calls.push(path)
      { text: "get: {}", format: @openapi.Yaml, source: "file:///" + path, }
    },
  )
  assert_eq(accepted.diagnostics.length(), 0)
  assert_true(calls.contains("parts/auth file.yaml"))
  assert_true(calls.contains("../other#file.yaml"))
}

///|
test "loader failures, invalid sources and malformed documents are request cached" {
  for mode in ["failure", "syntax", "identity"] {
    let calls : Array[String] = []
    let document = @openapi.parse_with_loader(
      entry_refs(["part.yaml", "part.yaml"]),
      format=@openapi.Json,
      source="file:///entry.json",
      load=(_, path) => {
        calls.push(path)
        match mode {
          "failure" => raise @openapi.DocumentError("source denied")
          "syntax" =>
            {
              text: "get: [}",
              format: @openapi.Yaml,
              source: "file:///part.yaml",
            }
          _ => { text: "get: {}", format: @openapi.Yaml, source: "", }
        }
      },
    )
    assert_eq(calls.length(), 1)
    assert_eq(document.operations.length(), 1)
    assert_eq(document.diagnostics.length(), 2)
    assert_eq(document.diagnostics[0].location.uri, "file:///entry.json")
    assert_eq(
      document.diagnostics[0].code,
      match mode {
        "failure" => "ref.load"
        "syntax" => "ref.input"
        _ => "ref.source"
      },
    )
  }
}

///|
test "canonical source cache rejects content or encoding conflicts" {
  for mode in ["content", "format"] {
    let document = @openapi.parse_with_loader(
      entry_refs(["first.json", "other.json"]),
      format=@openapi.Json,
      source="file:///entry.json",
      load=(_, path) => {
        let first = path == "first.json"
        {
          text: if !first && mode == "content" {
            "{\"post\":{}}"
          } else {
            "{\"get\":{}}"
          },
          format: if !first && mode == "format" {
            @openapi.Yaml
          } else {
            @openapi.Json
          },
          source: "file:///canonical.json",
        }
      },
    )
    assert_eq(document.diagnostics.length(), 1)
    assert_eq(document.diagnostics[0].code, "ref.conflict")
    assert_eq(document.operations.length(), 2)
  }
}

///|
test "document budget reserves capacity before invoking a new loader request" {
  let calls : Array[String] = []
  let document = @openapi.parse_with_loader(
    entry_refs(["next.json"]),
    format=@openapi.Json,
    source="file:///entry.json",
    load=(from, path) => {
      calls.push(path)
      {
        text: "{\"$ref\":\"next.json\"}",
        format: @openapi.Json,
        source: from + "/next",
      }
    },
  )
  assert_eq(calls.length(), 63)
  assert_eq(document.diagnostics[0].code, "resource.documents")
  assert_eq(document.operations.length(), 1)
}

///|
test "aggregate AST node budget retains operations parsed before exhaustion" {
  let items = Array::make(200000, "null").join(",")
  for format in [@openapi.Json, @openapi.Yaml] {
    let payload = if format == @openapi.Json {
      "{\"get\":{},\"x-data\":[" + items + "]}"
    } else {
      "get: {}\nx-data: [" + items + "]"
    }
    let document = @openapi.parse_with_loader(
      entry_refs(["a.json", "b.json", "c.json", "d.json", "e.json"]),
      format=@openapi.Json,
      source="file:///entry.json",
      load=(_, path) => { text: payload, format, source: "file:///" + path, },
    )
    assert_true(document.diagnostics.any(item => item.code == "resource.nodes"))
    assert_eq(document.operations.length(), 5)
  }
}

///|
test "aggregate encoded byte budget counts distinct canonical sources" {
  let payload = "{\"get\":{},\"x-padding\":\"" +
    String::make(15 * 1024 * 1024, 'a') +
    "\"}"
  let document = @openapi.parse_with_loader(
    entry_refs(["a.json", "b.json", "c.json", "d.json", "e.json"]),
    format=@openapi.Json,
    source="file:///entry.json",
    load=(_, path) => {
      text: payload,
      format: @openapi.Json,
      source: "file:///" + path,
    },
  )
  assert_true(document.diagnostics.any(item => item.code == "resource.bytes"))
  assert_eq(document.operations.length(), 5)
}
