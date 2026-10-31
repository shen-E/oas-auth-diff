///|
priv enum Expression {
  Character(Array[(Int32, Int32)])
  Begin
  End
  Concat(Array[Expression])
  Alternate(Array[Expression])
  Repeat(Expression, Int32, Int32?)
}

///|
priv struct PatternParser {
  chars : Array[Char]
  mut index : Int32
}

///|
fn PatternParser::peek(self : PatternParser) -> Char? {
  self.chars.get(self.index)
}

///|
fn PatternParser::take(self : PatternParser) -> Char raise SchemaError {
  match self.peek() {
    Some(char) => {
      self.index += 1
      char
    }
    None => raise SchemaError("Unexpected end of pattern")
  }
}

///|
fn PatternParser::hex(
  self : PatternParser,
  digits : Int32,
) -> Int32 raise SchemaError {
  let mut value = 0
  for _ in 0..<digits {
    let char = self.take()
    let digit = if char >= '0' && char <= '9' {
      char.to_int() - 48
    } else if char >= 'a' && char <= 'f' {
      char.to_int() - 87
    } else if char >= 'A' && char <= 'F' {
      char.to_int() - 55
    } else {
      raise SchemaError("Invalid hexadecimal pattern escape")
    }
    value = value * 16 + digit
  }
  if value >= 0xd800 && value <= 0xdfff {
    raise SchemaError("Surrogate pattern escapes require a code-unit policy")
  }
  value
}

///|
fn PatternParser::escaped(
  self : PatternParser,
  in_class : Bool,
) -> Array[(Int32, Int32)] raise SchemaError {
  let char = self.take()
  match char {
    'd' => [(48, 57)]
    'w' => [(48, 57), (65, 90), (95, 95), (97, 122)]
    // ECMAScript WhiteSpace and LineTerminator, not Unicode White_Space:
    // U+0085 and the former U+180E whitespace are deliberately absent.
    's' =>
      [
        (9, 13),
        (32, 32),
        (0xa0, 0xa0),
        (0x1680, 0x1680),
        (0x2000, 0x200a),
        (0x2028, 0x2029),
        (0x202f, 0x202f),
        (0x205f, 0x205f),
        (0x3000, 0x3000),
        (0xfeff, 0xfeff),
      ]
    'n' => [(10, 10)]
    'r' => [(13, 13)]
    't' => [(9, 9)]
    'f' => [(12, 12)]
    'v' => [(11, 11)]
    'b' if in_class => [(8, 8)]
    'x' => {
      let n = self.hex(2)
      [(n, n)]
    }
    'u' => {
      let n = self.hex(4)
      [(n, n)]
    }
    _ if "^$\\.*+?()[]{}|/".contains(char.to_string()) ||
      (in_class && char == '-') => {
      let n = char.to_int()
      [(n, n)]
    }
    _ => raise SchemaError("Unsupported pattern escape: \\" + char.to_string())
  }
}

///|
fn PatternParser::class_atom(
  self : PatternParser,
) -> Array[(Int32, Int32)] raise SchemaError {
  let char = self.take()
  if char == '\\' {
    self.escaped(true)
  } else {
    let n = char.to_int()
    [(n, n)]
  }
}

///|
fn PatternParser::character_class(
  self : PatternParser,
) -> Expression raise SchemaError {
  if self.peek() == Some('^') {
    raise SchemaError(
      "Negated pattern classes require Unicode/code-unit policy",
    )
  }
  let ranges = []
  while self.peek() != Some(']') {
    if self.peek() is None {
      raise SchemaError("Unclosed pattern character class")
    }
    let low = self.class_atom()
    if self.peek() == Some('-') && self.chars.get(self.index + 1) != Some(']') {
      self.index += 1
      let high = self.class_atom()
      if low.length() != 1 ||
        high.length() != 1 ||
        low[0].0 != low[0].1 ||
        high[0].0 != high[0].1 ||
        low[0].0 > high[0].0 {
        raise SchemaError("Invalid pattern character range")
      }
      if low[0].0 <= 0xdfff && high[0].0 >= 0xd800 {
        raise SchemaError("Pattern range crosses surrogate code units")
      }
      ranges.push((low[0].0, high[0].0))
    } else {
      ranges.append(low)
    }
  }
  self.index += 1
  Character(ranges)
}

///|
fn PatternParser::count(self : PatternParser) -> Int32 raise SchemaError {
  let mut value = 0
  let start = self.index
  while self.peek() is Some(char) && char >= '0' && char <= '9' {
    self.index += 1
    value = value * 10 + char.to_int() - 48
    if value > 64 {
      raise SchemaError("Pattern repetition exceeds 64")
    }
  }
  if self.index == start {
    raise SchemaError("Expected a pattern repetition count")
  }
  value
}

///|
fn PatternParser::sequence(
  self : PatternParser,
  depth : Int32,
) -> Expression raise SchemaError {
  let parts = []
  while self.peek() is Some(char) && char != ')' && char != '|' {
    self.index += 1
    let atom = match char {
      '^' => Begin
      '$' => End
      '[' => self.character_class()
      '\\' => Character(self.escaped(false))
      '(' => {
        if self.peek() == Some('?') {
          self.index += 1
          if self.take() != ':' {
            raise SchemaError(
              "Lookaround and inline pattern flags are unsupported",
            )
          }
        }
        let child = self.expression(depth + 1)
        if self.take() != ')' {
          raise SchemaError("Unclosed pattern group")
        }
        child
      }
      '.' => raise SchemaError("Pattern dot requires Unicode/code-unit policy")
      '*' | '+' | '?' | '{' | '}' | ']' =>
        raise SchemaError("Unexpected pattern metacharacter")
      _ => Character([(char.to_int(), char.to_int())])
    }
    let mut repeated = false
    let mut part = atom
    match self.peek() {
      Some('*') => {
        self.index += 1
        part = Repeat(atom, 0, None)
        repeated = true
      }
      Some('+') => {
        self.index += 1
        part = Repeat(atom, 1, None)
        repeated = true
      }
      Some('?') => {
        self.index += 1
        part = Repeat(atom, 0, Some(1))
        repeated = true
      }
      Some('{') => {
        self.index += 1
        let min = self.count()
        let max = if self.peek() == Some(',') {
          self.index += 1
          if self.peek() == Some('}') {
            None
          } else {
            Some(self.count())
          }
        } else {
          Some(min)
        }
        if self.take() != '}' || (max is Some(max) && max < min) {
          raise SchemaError("Invalid pattern repetition")
        }
        part = Repeat(atom, min, max)
        repeated = true
      }
      _ => ()
    }
    if repeated {
      if atom is Begin || atom is End {
        raise SchemaError("Pattern assertions cannot be quantified")
      }
      // Greediness changes match selection, not the set of accepted strings.
      if self.peek() == Some('?') {
        self.index += 1
      }
    }
    parts.push(part)
  }
  Concat(parts)
}

///|
fn PatternParser::expression(
  self : PatternParser,
  depth : Int32,
) -> Expression raise SchemaError {
  if depth > 32 {
    raise SchemaError("Pattern grouping exceeds 32 levels")
  }
  let branches = [self.sequence(depth)]
  while self.peek() == Some('|') {
    self.index += 1
    branches.push(self.sequence(depth))
  }
  if branches.length() == 1 {
    branches[0]
  } else {
    Alternate(branches)
  }
}
