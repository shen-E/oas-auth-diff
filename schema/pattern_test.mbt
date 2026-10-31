///|
test "patterns use unanchored ECMAScript search semantics and explicit anchors" {
  let cases : Array[(String, Array[String], Array[String])] = [
    ("cat", ["cat", "bobcat", "cat\n", "猫cat🚀"], ["", "CAT", "ca"]),
    ("^cat$", ["cat"], ["bobcat", "cat\n", "\ncat", "cat🚀"]),
    ("^a|b$", ["ax", "zb", "a\n", "🚀b"], ["xa", "by", "\nb\n"]),
    ("^(ab|cd)+$", ["ab", "abcd", "cdcd"], ["", "ac", "abc"]),
    ("^[a-z0-9_-]{2,4}$", ["ab", "_0", "ab-c"], ["a", "abcde", "猫猫"]),
    ("^\\d\\w?\\n$", ["1\n", "2_\n"], ["1a", "猫\n", "2é\n"]),
    ("^(?:a?)*$", ["", "a", "aaa"], ["b", "a\n"]),
    ("^a{2,}$", ["aa", "aaa"], ["", "a", "baa"]),
    ("[]", [], ["", "a", "🚀"]),
    ("", ["", "a", "🚀\n"], []),
  ]
  for (pattern, yes, no) in cases {
    let schema = @schema.parse({ "type": "string", "pattern": pattern })
    for text in yes {
      assert_true(schema.accepts(Json::string(text)))
    }
    for text in no {
      assert_false(schema.accepts(Json::string(text)))
    }
  }
  assert_true(@schema.parse({ "pattern": "^a$" }).accepts(Json::number(7)))
}

///|
test "pattern inclusion proves languages and produces independently evaluated witnesses" {
  for
    (wide, narrow) in [
      ("^[a-z]+$", "^[a-f]+$"),
      ("a", "^a$"),
      ("^(a|b)*$", "^a*$"),
      ("^a{1,4}$", "^a{2,3}$"),
      ("\\w+", "^[0-9]+$"),
      ("^a|b$", "^a$"),
      ("", "[]"),
    ] {
    let a = @schema.parse({ "type": "string", "pattern": wide })
    let b = @schema.parse({ "type": "string", "pattern": narrow })
    assert_true(@schema.subset(b, a) is Included)
    match @schema.subset(a, b) {
      Excluded(value) => {
        assert_true(a.accepts(value))
        assert_false(b.accepts(value))
      }
      _ => fail("expected a pattern counterexample: " + wide + " -> " + narrow)
    }
  }
  let a = @schema.parse({ "type": "string", "pattern": "^(ab|ac)$" })
  let b = @schema.parse({ "type": "string", "pattern": "^a[bc]$" })
  assert_true(@schema.subset(a, b) is Included)
  assert_true(@schema.subset(b, a) is Included)
}

///|
test "pattern intersections account for string lengths and nested witnesses" {
  let a = @schema.parse({
    "type": "string",
    "allOf": [{ "pattern": "^[a-z]+$" }, { "pattern": "^a[abc]*$" }],
    "maxLength": 3,
  })
  let b = @schema.parse({ "type": "string", "pattern": "^a[abc]{0,2}$" })
  assert_true(@schema.subset(a, b) is Included)
  assert_true(@schema.subset(b, a) is Included)
  let old = @schema.parse({
    "type": "object",
    "properties": { "id": { "type": "string", "pattern": "^[0-9]+$" } },
    "required": ["id"],
  })
  let next = @schema.parse({
    "type": "object",
    "properties": { "id": { "type": "string", "pattern": "^[0-9]{3}$" } },
    "required": ["id"],
  })
  assert_true(@schema.subset(old, next) is Excluded(_))
  let big = @schema.parse({
    "type": "string",
    "minLength": 10000,
    "pattern": "^[a-z]+$",
  })
  assert_true(
    @schema.subset(
      big,
      @schema.parse({ "type": "string", "pattern": "^[a-z]*$" }),
    )
    is Included,
  )
}

///|
test "unsupported pattern syntax and resource limits produce typed errors" {
  for
    pattern in [
      ".", "[^a]", "(?=a)", "(a)\\1", "\\p{L}", "🚀", "a{65}", "(", "a{2,1}", "[z-a]",
      "a**", "\\q", "(a{64}){64}", "\\uD800", "\\uDFFF", "[\\uD7FF-\\uE000]",
    ] {
    let refused = try {
      ignore(@schema.parse({ "pattern": pattern }))
      false
    } catch {
      @schema.SchemaError(_) => true
    }
    assert_true(refused)
  }
}

///|
test "BMP atoms and ECMAScript whitespace preserve scalar string lengths" {
  let whitespace = @schema.parse({ "type": "string", "pattern": "^\\s$" })
  for
    text in [
      " ", "\t", "\n", "\r", "\u{000b}", "\u{000c}", "\u{00a0}", "\u{1680}", "\u{2000}",
      "\u{200a}", "\u{2028}", "\u{2029}", "\u{202f}", "\u{205f}", "\u{3000}", "\u{feff}",
    ] {
    assert_true(whitespace.accepts(Json::string(text)))
  }
  for text in ["", "  ", "\u{0085}", "\u{180e}", "\u{200b}", "猫", "🚀"] {
    assert_false(whitespace.accepts(Json::string(text)))
  }
  let wide = @schema.parse({ "type": "string", "pattern": "^[一-龥é]+$" })
  let narrow = @schema.parse({ "type": "string", "pattern": "^[猫é]+$" })
  assert_true(@schema.subset(narrow, wide) is Included)
  match @schema.subset(wide, narrow) {
    Excluded(value) => {
      assert_true(wide.accepts(value))
      assert_false(narrow.accepts(value))
    }
    _ => fail("expected a Unicode language witness")
  }
  let escaped = @schema.parse({
    "type": "string",
    "pattern": "^\\u732b\\xE9$",
    "maxLength": 2,
  })
  assert_true(escaped.accepts(Json::string("猫é")))
  assert_false(escaped.accepts(Json::string("猫é🚀")))
  assert_true(
    @schema.parse({ "pattern": "猫" }).accepts(Json::string("🚀猫🚀")),
  )
}

///|
test "pattern product exhaustion remains unknown" {
  let a = @schema.parse({ "type": "string", "pattern": "^[ab]*a[ab]{12}$" })
  let b = @schema.parse({ "type": "string", "pattern": "^[ab]*b[ab]{12}$" })
  assert_true(@schema.subset(a, b) is Unknown(_))
}

///|
test "finite pattern languages agree with an independent finite-set oracle" {
  let patterns = [
    "^(a|b)$", "^a$", "^b$", "^ab$", "^(a|ab)$", "^a?$", "^$", "[]",
  ]
  let expected = [
    ["a", "b"],
    ["a"],
    ["b"],
    ["ab"],
    ["a", "ab"],
    ["", "a"],
    [""],
    [],
  ]
  for index, pattern in patterns {
    let source = @schema.parse({ "type": "string", "pattern": pattern })
    for other, target in patterns {
      let target = @schema.parse({ "type": "string", "pattern": target })
      let included = expected[index].all(s => expected[other].contains(s))
      match @schema.subset(source, target) {
        Included => assert_true(included)
        Excluded(value) => {
          assert_false(included)
          assert_true(source.accepts(value))
          assert_false(target.accepts(value))
        }
        Unknown(message) => fail(message)
      }
    }
  }
}
