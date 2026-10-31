///|
priv enum StringRelation {
  Covered
  Different(String)
  Undecided
}

///|
priv struct StringState {
  left : Array[Array[Int32]]
  right : Array[Array[Int32]]
  length : Int32
  parent : Int32
  symbol : Int32
}

///|
fn string_state_key(state : StringState) -> String {
  let value : Json = [
    Json(state.left),
    Json(state.right),
    Json(state.length),
    Json(state.parent == -1),
  ]
  value.stringify()
}

///|
fn pattern_alphabet(patterns : Array[Pattern]) -> Array[Int32] {
  let boundaries = [0, 128, 0xd800, 0xe000, 0x110000]
  for pattern in patterns {
    for state in pattern.states {
      for (low, high, _) in state.edges {
        if !boundaries.contains(low) {
          boundaries.push(low)
        }
        if !boundaries.contains(high + 1) {
          boundaries.push(high + 1)
        }
      }
    }
  }
  boundaries.sort()
  let result = []
  for index in 0..<(boundaries.length() - 1) {
    let low = boundaries[index]
    let high = boundaries[index + 1] - 1
    if low >= 0xd800 && high < 0xe000 {
      continue
    }
    let representative = if low <= 97 && high >= 97 {
      97
    } else if low <= 48 && high >= 48 {
      48
    } else if low <= 32 && high >= 32 {
      32
    } else if low <= 233 && high >= 233 {
      233
    } else {
      low
    }
    result.push(representative)
  }
  result
}

///|
fn patterns_accept(
  patterns : Array[Pattern],
  states : Array[Array[Int32]],
  begin : Bool,
  budget : Budget,
) -> Bool raise SchemaError {
  for index, pattern in patterns {
    if !pattern_close(pattern, states[index], begin, true, budget).contains(
        pattern.accept,
      ) {
      return false
    }
  }
  true
}

///|
fn pattern_witness(states : Array[StringState], index : Int32) -> String {
  let symbols = []
  let mut cursor = index
  while states[cursor].parent >= 0 {
    symbols.push(states[cursor].symbol)
    cursor = states[cursor].parent
  }
  let out = StringBuilder()
  for index = symbols.length() - 1; index >= 0; index = index - 1 {
    out.write_char(symbols[index].to_char().unwrap())
  }
  out.to_string()
}

///|
fn language_search(
  left : Array[Pattern],
  left_size : Bounds,
  right : Array[Pattern]?,
  right_size : Bounds,
  budget : Budget,
) -> StringRelation raise SchemaError {
  let mut cap = 0
  for
    bound in [
      left_size.lower,
      left_size.upper,
      right_size.lower,
      right_size.upper,
    ] {
    if bound is Some(bound) {
      match bound.value {
        Number(n, ..) if n >= 0 && n <= 128 =>
          if n.to_int() + 1 > cap {
            cap = n.to_int() + 1
          }
        _ => return Undecided
      }
    }
  }
  let target = right.unwrap_or([])
  let all = left.copy()
  all.append(target)
  let alphabet = pattern_alphabet(all)
  let first : StringState = {
    left: left.map(p => pattern_close(p, [p.start], true, false, budget)),
    right: target.map(p => pattern_close(p, [p.start], true, false, budget)),
    length: 0,
    parent: -1,
    symbol: 0,
  }
  let states = [first]
  let seen = Map([(string_state_key(first), true)])
  let mut cursor = 0
  while cursor < states.length() {
    consume(budget)
    let state = states[cursor]
    let size = Json::number(state.length.to_double())
    if within(left_size, size) &&
      patterns_accept(left, state.left, state.parent == -1, budget) &&
      (
        right is None ||
        !within(right_size, size) ||
        !patterns_accept(target, state.right, state.parent == -1, budget)
      ) {
      return Different(pattern_witness(states, cursor))
    }
    if !state.left.any(s => s.is_empty()) {
      for symbol in alphabet {
        let next : StringState = {
          left: left.mapi((index, p) => {
            pattern_move(p, state.left[index], symbol, budget)
          }),
          right: target.mapi((index, p) => {
            pattern_move(p, state.right[index], symbol, budget)
          }),
          length: if state.length < cap {
            state.length + 1
          } else {
            cap
          },
          parent: cursor,
          symbol,
        }
        let key = string_state_key(next)
        if !seen.contains(key) {
          if states.length() >= 4096 {
            return Undecided
          }
          seen[key] = true
          states.push(next)
        }
      }
    }
    cursor += 1
  }
  Covered
}

///|
fn string_relation(
  left : Constraints,
  right : Constraints,
  budget : Budget,
) -> StringRelation raise SchemaError {
  if bounds_imply(left.length, right.length) &&
    right.patterns.all(p => left.patterns.any(q => p.text == q.text)) {
    return Covered
  }
  let result = language_search(
    left.patterns,
    left.length,
    Some(right.patterns),
    right.length,
    budget,
  )
  if !(result is Undecided) {
    return result
  }
  // Proving pattern inclusion alone is sufficient when the length implication
  // holds, even if length bounds exceed the product counter's finite profile.
  match
    language_search(
      left.patterns,
      empty_bounds(),
      Some(right.patterns),
      empty_bounds(),
      budget,
    ) {
    Covered if bounds_imply(left.length, right.length) => Covered
    Different(text) if within(
        left.length,
        Json::number(text.iter().count().to_double()),
      ) &&
      (
        !within(right.length, Json::number(text.iter().count().to_double())) ||
        !right.patterns.all(p => pattern_accepts(p, text, budget))
      ) => Different(text)
    _ => Undecided
  }
}
