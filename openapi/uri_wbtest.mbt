///|
fn uri_test_location() -> Location {
  {
    uri: "file:///api.json",
    pointer: "/components/securitySchemes/OAuth/flows/clientCredentials/tokenUrl",
  }
}

///|
// RFC 3986 sections 5.4.1 and 5.4.2. HTTP's empty path is normalized to /.
test "URI RFC 3986 normal and abnormal reference vectors" {
  let base = "http://a/b/c/d;p?q"
  let cases = [
    ("g", "http://a/b/c/g"),
    ("./g", "http://a/b/c/g"),
    ("g/", "http://a/b/c/g/"),
    ("/g", "http://a/g"),
    ("//g", "http://g/"),
    ("?y", "http://a/b/c/d;p?y"),
    ("g?y", "http://a/b/c/g?y"),
    (";x", "http://a/b/c/;x"),
    ("g;x", "http://a/b/c/g;x"),
    ("", "http://a/b/c/d;p?q"),
    (".", "http://a/b/c/"),
    ("./", "http://a/b/c/"),
    ("..", "http://a/b/"),
    ("../", "http://a/b/"),
    ("../g", "http://a/b/g"),
    ("../..", "http://a/"),
    ("../../", "http://a/"),
    ("../../g", "http://a/g"),
    ("../../../g", "http://a/g"),
    ("../../../../g", "http://a/g"),
    ("/./g", "http://a/g"),
    ("/../g", "http://a/g"),
    ("g.", "http://a/b/c/g."),
    (".g", "http://a/b/c/.g"),
    ("g..", "http://a/b/c/g.."),
    ("..g", "http://a/b/c/..g"),
    ("./../g", "http://a/b/g"),
    ("./g/.", "http://a/b/c/g/"),
    ("g/./h", "http://a/b/c/g/h"),
    ("g/../h", "http://a/b/c/h"),
    ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
    ("g;x=1/../y", "http://a/b/c/y"),
    ("g?y/./x", "http://a/b/c/g?y/./x"),
    ("g?y/../x", "http://a/b/c/g?y/../x"),
  ]
  for (reference, expected) in cases {
    assert_eq(
      resolve_http_url(reference, Some(base), uri_test_location()),
      expected,
    )
  }
}

///|
test "URI merging preserves slash query and escape boundaries" {
  let cases = [
    ("token", "https://api.example/v1/", "https://api.example/v1/token"),
    ("token", "https://api.example/v1", "https://api.example/token"),
    ("token", "https://api.example", "https://api.example/token"),
    ("token", "https://api.example/a/..", "https://api.example/a/token"),
    ("?", "https://api.example/token?old", "https://api.example/token?"),
    ("token?", "https://api.example/a?old", "https://api.example/token?"),
    ("", "https://api.example/token?old", "https://api.example/token?old"),
    ("a//b", "https://api.example/base/", "https://api.example/base/a//b"),
    ("/a//../b", "https://api.example/", "https://api.example/a/b"),
    ("/a///..", "https://api.example/", "https://api.example/a//"),
    (
      "%2e/%2e%2e/token", "https://api.example/base/", "https://api.example/base/%2E/%2E%2E/token",
    ),
    (
      "a%2fb?next=%2f..%2fsecret", "https://api.example/", "https://api.example/a%2Fb?next=%2F..%2Fsecret",
    ),
    ("caf%c3%a9", "https://api.example/", "https://api.example/caf%C3%A9"),
    (
      "//OTHER.example:443/token", "https://api.example/base/", "https://other.example/token",
    ),
  ]
  for (reference, base, expected) in cases {
    assert_eq(
      resolve_http_url(reference, Some(base), uri_test_location()),
      expected,
    )
  }
}

///|
test "URI canonical HTTP authority handles ports IPv4 and IPv6" {
  let cases = [
    ("HTTP://EXAMPLE.COM:80", "http://example.com/"),
    ("https://EXAMPLE.COM:00443/token", "https://example.com/token"),
    ("http://example.com:/token", "http://example.com/token"),
    ("https://example.com:0/token", "https://example.com:0/token"),
    ("https://example.com:65535/token", "https://example.com:65535/token"),
    ("https://EXAMPLE.com./token", "https://example.com./token"),
    ("https://127.0.0.1:0443/token", "https://127.0.0.1/token"),
    (
      "https://[2001:0DB8:0000:0000:0000:0000:0000:0001]:443/token", "https://[2001:db8::1]/token",
    ),
    ("https://[2001:db8::1]:8443/token", "https://[2001:db8::1]:8443/token"),
    ("http://[0:0:0:0:0:0:0:0]:80/", "http://[::]/"),
    ("http://[::FFFF:192.0.2.1]/", "http://[::ffff:c000:201]/"),
    ("http://[1:0:0:2:0:0:3:4]/", "http://[1::2:0:0:3:4]/"),
    ("https://example.com/a/../token", "https://example.com/token"),
  ]
  for (reference, expected) in cases {
    assert_eq(resolve_http_url(reference, None, uri_test_location()), expected)
  }
  assert_eq(
    resolve_http_url(
      "https://host/token",
      Some("invalid base"),
      uri_test_location(),
    ),
    "https://host/token",
  )
}

///|
test "URI invalid and unsupported authentication addresses retain location" {
  let cases = [
    "ftp://host/token", "http:token", "http:/token", "http:///token", "https://",
    "https://user:secret@host/token", "https://user@host/token", "https://host/token#",
    "https://host/token#fragment", "https://bad host/token", "https://host\\token",
    "https://host/\n", "https://host/\u0000", "https://host/%", "https://host/%1",
    "https://host/%GG", "https://host/café", "https://host/a[b]", "https://host/?q=[x]",
    "https://host:bad/", "https://host:-1/", "https://host:65536/", "https://host:12345678901234567890/",
    "https://:443/", "https://a..b/", "https://-host/", "https://host-/", "https://host_name/",
    "https://999.1.2.3/", "https://127.1/", "https://0127.0.0.1/", "https://%40host/",
    "https://[::1", "https://::1/", "https://[]/", "https://[:::1]/", "https://[1:2:3]/",
    "https://[1:2:3:4:5:6:7:8:9]/", "https://[1:2:3:4:5:6:7:8::]/", "https://[::ffff:999.0.0.1]/",
    "https://[v1.example]/", "https://[fe80::1%25eth0]/", "https://[::1]suffix/",
    "https://[::1]:bad/", "https://[::1]:65536/", "g:h", "http:g", "#s", "g#s", "g?y#s",
    "g;x?y#s", "g#s/./x", "g#s/../x",
  ]
  let location = uri_test_location()
  for reference in cases {
    try
      resolve_http_url(reference, Some("http://a/b/c/d;p?q"), location)
    catch {
      AuthError(code, _, at) => {
        assert_eq(code, "auth.url")
        assert_eq(at, location)
      }
    } noraise {
      _ => fail("expected invalid authentication URL: " + reference)
    }
  }
  for reference in ["token", "/token", "//host/token", ""] {
    try resolve_http_url(reference, None, location) catch {
      AuthError(code, _, _) => assert_eq(code, "auth.url")
    } noraise {
      _ => fail("expected missing-base failure")
    }
  }
  for
    base in [
      "relative", "file:///api.json", "https://", "https://host/base#fragment", "https://user@host/",
    ] {
    try resolve_http_url("token", Some(base), location) catch {
      AuthError(code, _, _) => assert_eq(code, "auth.url")
    } noraise {
      _ => fail("expected invalid-base failure")
    }
  }
}

///|
// Expected values generated independently with Python urllib.parse.urljoin.
// Only HTTP empty-path and percent-escape spelling are canonicalized here.
// Empty-query and repeated relative slashes use the explicit RFC tests above.
test "URI Python urljoin differential reference fixtures" {
  let cases = [
    ("token", "http://a/b/c/d;p?q", "http://a/b/c/token"),
    ("./token", "http://a/b/c/d;p?q", "http://a/b/c/token"),
    ("../token", "http://a/b/c/d;p?q", "http://a/b/token"),
    ("../../token", "http://a/b/c/d;p?q", "http://a/token"),
    ("../../../token", "http://a/b/c/d;p?q", "http://a/token"),
    ("/token", "http://a/b/c/d;p?q", "http://a/token"),
    ("/a/./b/../token", "http://a/b/c/d;p?q", "http://a/a/token"),
    ("?aud=one", "http://a/b/c/d;p?q", "http://a/b/c/d;p?aud=one"),
    ("token?next=/../x", "http://a/b/c/d;p?q", "http://a/b/c/token?next=/../x"),
    ("token;v=1", "http://a/b/c/d;p?q", "http://a/b/c/token;v=1"),
    (
      "//other.example/token", "http://a/b/c/d;p?q", "http://other.example/token",
    ),
    (
      "https://other.example/token", "http://a/b/c/d;p?q", "https://other.example/token",
    ),
    ("a%2Fb", "http://a/b/c/d;p?q", "http://a/b/c/a%2Fb"),
    ("./%2E/token", "http://a/b/c/d;p?q", "http://a/b/c/%2E/token"),
    ("a/../../token", "http://a/b/c/d;p?q", "http://a/b/token"),
    ("", "http://a/b/c/d;p?q", "http://a/b/c/d;p?q"),
    (".", "http://a/b/c/d;p?q", "http://a/b/c/"),
    ("..", "http://a/b/c/d;p?q", "http://a/b/"),
    ("./", "http://a/b/c/d;p?q", "http://a/b/c/"),
    ("../", "http://a/b/c/d;p?q", "http://a/b/"),
    ("/", "http://a/b/c/d;p?q", "http://a/"),
    ("../t/", "http://a/b/c/d;p?q", "http://a/b/t/"),
    ("/a//b", "http://a/b/c/d;p?q", "http://a/a//b"),
    ("a%3Fb?x=%2F", "http://a/b/c/d;p?q", "http://a/b/c/a%3Fb?x=%2F"),
    ("token", "https://api.example/v1/", "https://api.example/v1/token"),
    ("./token", "https://api.example/v1/", "https://api.example/v1/token"),
    ("../token", "https://api.example/v1/", "https://api.example/token"),
    ("../../token", "https://api.example/v1/", "https://api.example/token"),
    ("../../../token", "https://api.example/v1/", "https://api.example/token"),
    ("/token", "https://api.example/v1/", "https://api.example/token"),
    (
      "/a/./b/../token", "https://api.example/v1/", "https://api.example/a/token",
    ),
    ("?aud=one", "https://api.example/v1/", "https://api.example/v1/?aud=one"),
    (
      "token?next=/../x", "https://api.example/v1/", "https://api.example/v1/token?next=/../x",
    ),
    ("token;v=1", "https://api.example/v1/", "https://api.example/v1/token;v=1"),
    (
      "//other.example/token", "https://api.example/v1/", "https://other.example/token",
    ),
    (
      "https://other.example/token", "https://api.example/v1/", "https://other.example/token",
    ),
    ("a%2Fb", "https://api.example/v1/", "https://api.example/v1/a%2Fb"),
    (
      "./%2E/token", "https://api.example/v1/", "https://api.example/v1/%2E/token",
    ),
    ("a/../../token", "https://api.example/v1/", "https://api.example/token"),
    ("", "https://api.example/v1/", "https://api.example/v1/"),
    (".", "https://api.example/v1/", "https://api.example/v1/"),
    ("..", "https://api.example/v1/", "https://api.example/"),
    ("./", "https://api.example/v1/", "https://api.example/v1/"),
    ("../", "https://api.example/v1/", "https://api.example/"),
    ("/", "https://api.example/v1/", "https://api.example/"),
    ("../t/", "https://api.example/v1/", "https://api.example/t/"),
    ("/a//b", "https://api.example/v1/", "https://api.example/a//b"),
    (
      "a%3Fb?x=%2F", "https://api.example/v1/", "https://api.example/v1/a%3Fb?x=%2F",
    ),
    ("token", "https://api.example/v1", "https://api.example/token"),
    ("./token", "https://api.example/v1", "https://api.example/token"),
    ("../token", "https://api.example/v1", "https://api.example/token"),
    ("../../token", "https://api.example/v1", "https://api.example/token"),
    ("../../../token", "https://api.example/v1", "https://api.example/token"),
    ("/token", "https://api.example/v1", "https://api.example/token"),
    ("/a/./b/../token", "https://api.example/v1", "https://api.example/a/token"),
    ("?aud=one", "https://api.example/v1", "https://api.example/v1?aud=one"),
    (
      "token?next=/../x", "https://api.example/v1", "https://api.example/token?next=/../x",
    ),
    ("token;v=1", "https://api.example/v1", "https://api.example/token;v=1"),
    (
      "//other.example/token", "https://api.example/v1", "https://other.example/token",
    ),
    (
      "https://other.example/token", "https://api.example/v1", "https://other.example/token",
    ),
    ("a%2Fb", "https://api.example/v1", "https://api.example/a%2Fb"),
    ("./%2E/token", "https://api.example/v1", "https://api.example/%2E/token"),
    ("a/../../token", "https://api.example/v1", "https://api.example/token"),
    ("", "https://api.example/v1", "https://api.example/v1"),
    (".", "https://api.example/v1", "https://api.example/"),
    ("..", "https://api.example/v1", "https://api.example/"),
    ("./", "https://api.example/v1", "https://api.example/"),
    ("../", "https://api.example/v1", "https://api.example/"),
    ("/", "https://api.example/v1", "https://api.example/"),
    ("../t/", "https://api.example/v1", "https://api.example/t/"),
    ("/a//b", "https://api.example/v1", "https://api.example/a//b"),
    ("a%3Fb?x=%2F", "https://api.example/v1", "https://api.example/a%3Fb?x=%2F"),
    ("token", "https://api.example/", "https://api.example/token"),
    ("./token", "https://api.example/", "https://api.example/token"),
    ("../token", "https://api.example/", "https://api.example/token"),
    ("../../token", "https://api.example/", "https://api.example/token"),
    ("../../../token", "https://api.example/", "https://api.example/token"),
    ("/token", "https://api.example/", "https://api.example/token"),
    ("/a/./b/../token", "https://api.example/", "https://api.example/a/token"),
    ("?aud=one", "https://api.example/", "https://api.example/?aud=one"),
    (
      "token?next=/../x", "https://api.example/", "https://api.example/token?next=/../x",
    ),
    ("token;v=1", "https://api.example/", "https://api.example/token;v=1"),
    (
      "//other.example/token", "https://api.example/", "https://other.example/token",
    ),
    (
      "https://other.example/token", "https://api.example/", "https://other.example/token",
    ),
    ("a%2Fb", "https://api.example/", "https://api.example/a%2Fb"),
    ("./%2E/token", "https://api.example/", "https://api.example/%2E/token"),
    ("a/../../token", "https://api.example/", "https://api.example/token"),
    ("", "https://api.example/", "https://api.example/"),
    (".", "https://api.example/", "https://api.example/"),
    ("..", "https://api.example/", "https://api.example/"),
    ("./", "https://api.example/", "https://api.example/"),
    ("../", "https://api.example/", "https://api.example/"),
    ("/", "https://api.example/", "https://api.example/"),
    ("../t/", "https://api.example/", "https://api.example/t/"),
    ("/a//b", "https://api.example/", "https://api.example/a//b"),
    ("a%3Fb?x=%2F", "https://api.example/", "https://api.example/a%3Fb?x=%2F"),
    ("token", "https://api.example?tenant=one", "https://api.example/token"),
    ("./token", "https://api.example?tenant=one", "https://api.example/token"),
    ("../token", "https://api.example?tenant=one", "https://api.example/token"),
    (
      "../../token", "https://api.example?tenant=one", "https://api.example/token",
    ),
    (
      "../../../token", "https://api.example?tenant=one", "https://api.example/token",
    ),
    ("/token", "https://api.example?tenant=one", "https://api.example/token"),
    (
      "/a/./b/../token", "https://api.example?tenant=one", "https://api.example/a/token",
    ),
    (
      "?aud=one", "https://api.example?tenant=one", "https://api.example/?aud=one",
    ),
    (
      "token?next=/../x", "https://api.example?tenant=one", "https://api.example/token?next=/../x",
    ),
    (
      "token;v=1", "https://api.example?tenant=one", "https://api.example/token;v=1",
    ),
    (
      "//other.example/token", "https://api.example?tenant=one", "https://other.example/token",
    ),
    (
      "https://other.example/token", "https://api.example?tenant=one", "https://other.example/token",
    ),
    ("a%2Fb", "https://api.example?tenant=one", "https://api.example/a%2Fb"),
    (
      "./%2E/token", "https://api.example?tenant=one", "https://api.example/%2E/token",
    ),
    (
      "a/../../token", "https://api.example?tenant=one", "https://api.example/token",
    ),
    ("", "https://api.example?tenant=one", "https://api.example/?tenant=one"),
    (".", "https://api.example?tenant=one", "https://api.example/"),
    ("..", "https://api.example?tenant=one", "https://api.example/"),
    ("./", "https://api.example?tenant=one", "https://api.example/"),
    ("../", "https://api.example?tenant=one", "https://api.example/"),
    ("/", "https://api.example?tenant=one", "https://api.example/"),
    ("../t/", "https://api.example?tenant=one", "https://api.example/t/"),
    ("/a//b", "https://api.example?tenant=one", "https://api.example/a//b"),
    (
      "a%3Fb?x=%2F", "https://api.example?tenant=one", "https://api.example/a%3Fb?x=%2F",
    ),
    (
      "token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/token",
    ),
    (
      "./token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/token",
    ),
    (
      "../token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/token",
    ),
    (
      "../../token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/token",
    ),
    (
      "../../../token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/token",
    ),
    ("/token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/token"),
    (
      "/a/./b/../token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/a/token",
    ),
    (
      "?aud=one", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/?aud=one",
    ),
    (
      "token?next=/../x", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/token?next=/../x",
    ),
    (
      "token;v=1", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/token;v=1",
    ),
    (
      "//other.example/token", "https://[2001:db8::1]/api/v1/", "https://other.example/token",
    ),
    (
      "https://other.example/token", "https://[2001:db8::1]/api/v1/", "https://other.example/token",
    ),
    (
      "a%2Fb", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/a%2Fb",
    ),
    (
      "./%2E/token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/%2E/token",
    ),
    (
      "a/../../token", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/token",
    ),
    ("", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/"),
    (".", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/"),
    ("..", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/"),
    ("./", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/"),
    ("../", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/"),
    ("/", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/"),
    ("../t/", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/t/"),
    ("/a//b", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/a//b"),
    (
      "a%3Fb?x=%2F", "https://[2001:db8::1]/api/v1/", "https://[2001:db8::1]/api/v1/a%3Fb?x=%2F",
    ),
  ]
  for (reference, base, expected) in cases {
    assert_eq(
      resolve_http_url(reference, Some(base), uri_test_location()),
      expected,
    )
  }
}
