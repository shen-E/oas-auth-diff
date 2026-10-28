///|
test "SARIF source roots are local directory URIs with stable drive and escape spelling" {
  for
    (input, expected) in [
      ("file:///", "file:///"),
      ("file:///home/ci/repo", "file:///home/ci/repo/"),
      ("file:///home/ci/repo/", "file:///home/ci/repo/"),
      ("FILE:///c:/Repo%20Copy", "file:///C:/Repo%20Copy/"),
      ("file:///d:/Specs/%e4%b8%ad", "file:///D:/Specs/%E4%B8%AD/"),
      ("file:///var/spec%23%3f%25", "file:///var/spec%23%3F%25/"),
    ] {
    assert_eq(SarifSourceRoot::new(input).uri(), expected)
  }
}

///|
test "SARIF roots reject ambiguous URI structure and dangerous path escapes" {
  for
    uri in [
      "", "/repo", "repo", "file:/repo", "file://repo", "file://localhost/repo",
      "file:////server/repo", "https://example.test/repo", "file:///repo?query",
      "file:///repo#fragment", "file:///repo name", "file:///中文", "file:///a\\b",
      "file:///a\n", "file:///a\u{0000}", "file:///a%", "file:///a%0", "file:///a%XY",
      "file:///a%00", "file:///a%1f", "file:///a%7f", "file:///a%2fb", "file:///a%5Cb",
      "file:///a/./b", "file:///a/../b", "file:///a/%2e/b", "file:///a/%2E./b", "file:///a/.%2e/b",
      "file:///a/%2e%2e/b", "file:///a//b", "file:///a//",
    ] {
    let rejected = try {
      ignore(SarifSourceRoot::new(uri))
      false
    } catch {
      InvalidSourceRoot(message) => {
        assert_true(message.contains("file:///"))
        true
      }
    }
    assert_true(rejected)
  }
}

///|
test "SARIF file identities preserve URI filename bytes and normalize only safe syntax" {
  for
    (input, expected) in [
      ("file:///repo/spec.yaml", "file:///repo/spec.yaml"),
      (
        "FILE:///c:/Repo/api%3a%20%23%3f%25.yaml", "file:///C:/Repo/api%3A%20%23%3F%25.yaml",
      ),
      ("file:///repo/%2efile.yaml", "file:///repo/%2Efile.yaml"),
      ("file:///repo/%252e%252e.yaml", "file:///repo/%252e%252e.yaml"),
      ("file:///repo/%e4%b8%ad.yaml", "file:///repo/%E4%B8%AD.yaml"),
    ] {
    assert_eq(sarif_file_identity(input), Some(expected))
  }
  for
    source in [
      "<input>", "relative.yaml", "https://example.test/spec.yaml", "file://host/repo/spec.yaml",
      "file:///repo/../spec.yaml", "file:///repo/%2E%2e/spec.yaml", "file:///repo/a%2Fspec.yaml",
      "file:///repo/a%5cspec.yaml", "file:///repo/a%00.yaml", "file:///repo/spec.yaml?revision=1",
      "file:///repo/spec.yaml#part",
    ] {
    assert_eq(sarif_file_identity(source), None)
  }
}

///|
test "SARIF relative locations require a complete case-sensitive root segment" {
  let root = SarifSourceRoot::new("file:///repo")
  for
    (source, expected) in [
      ("file:///repo/api.yaml", "api.yaml"),
      ("file:///repo/nested/api.yaml", "nested/api.yaml"),
      ("file:///repo/api:v1.yaml", "./api:v1.yaml"),
      ("file:///repo/dir:name/api.yaml", "./dir:name/api.yaml"),
      ("file:///repo/dir/api:v1.yaml", "dir/api:v1.yaml"),
      ("file:///repo/%23%3f%25%20%e4%b8%ad.yaml", "%23%3F%25%20%E4%B8%AD.yaml"),
      ("file:///repo/%3afile.yaml", "%3Afile.yaml"),
    ] {
    assert_eq(sarif_relative_uri(source, root), Some(expected))
  }
  for
    source in [
      "file:///repository/api.yaml", "file:///repo-old/api.yaml", "file:///Repo/api.yaml",
      "file:///repo", "file:///other/repo/api.yaml", "file:///repo/sub/../api.yaml",
      "file:///repo/sub/%2E%2E/api.yaml", "file:///repo//api.yaml", "file:///repo/%2fapi.yaml",
      "file:///repo/%5capi.yaml", "file://host/repo/api.yaml", "https://example.test/repo/api.yaml",
    ] {
    assert_eq(sarif_relative_uri(source, root), None)
  }
}

///|
test "SARIF Windows roots normalize drive case while preserving directory spelling" {
  let root = SarifSourceRoot::new("file:///c:/Work/Repo/")
  assert_eq(
    sarif_relative_uri("FILE:///C:/Work/Repo/spec.yaml", root),
    Some("spec.yaml"),
  )
  for
    source in [
      "file:///D:/Work/Repo/spec.yaml", "file:///C:/Work/repo/spec.yaml", "file:///C:/Work/Repository/spec.yaml",
      "file:///C:/Work/Repo/../spec.yaml",
    ] {
    assert_eq(sarif_relative_uri(source, root), None)
  }
  assert_eq(
    sarif_relative_uri("file:///C:/api.yaml", SarifSourceRoot::new("file:///")),
    Some("./C:/api.yaml"),
  )
}

///|
test "SARIF root errors expose their validation message through Show and to_string" {
  let error = InvalidSourceRoot("invalid directory")
  assert_eq(error.to_string(), "invalid directory")
  assert_eq("\{error}", "invalid directory")
}
