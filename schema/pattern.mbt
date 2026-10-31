///|
priv struct PatternState {
  epsilon : Array[Int32]
  begin : Array[Int32]
  end : Array[Int32]
  edges : Array[(Int32, Int32, Int32)]
}

///|
priv struct Pattern {
  text : String
  states : Array[PatternState]
  start : Int32
  accept : Int32
}

///|
fn new_state(states : Array[PatternState]) -> Int32 raise SchemaError {
  if states.length() >= 256 {
    raise SchemaError("Pattern NFA exceeds 256 states")
  }
  let index = states.length()
  states.push({ epsilon: [], begin: [], end: [], edges: [], })
  index
}

///|
fn compile_expression(
  expression : Expression,
  states : Array[PatternState],
) -> (Int32, Int32) raise SchemaError {
  let start = new_state(states)
  let end = new_state(states)
  match expression {
    Character(ranges) =>
      for (low, high) in ranges {
        states[start].edges.push((low, high, end))
      }
    Begin => states[start].begin.push(end)
    End => states[start].end.push(end)
    Concat(children) => {
      let mut cursor = start
      for child in children {
        let (s, e) = compile_expression(child, states)
        states[cursor].epsilon.push(s)
        cursor = e
      }
      states[cursor].epsilon.push(end)
    }
    Alternate(children) =>
      for child in children {
        let (s, e) = compile_expression(child, states)
        states[start].epsilon.push(s)
        states[e].epsilon.push(end)
      }
    Repeat(child, min, max) => {
      let mut cursor = start
      for _ in 0..<min {
        let (s, e) = compile_expression(child, states)
        states[cursor].epsilon.push(s)
        cursor = e
      }
      match max {
        None => {
          let (s, e) = compile_expression(child, states)
          states[cursor].epsilon.push(end)
          states[cursor].epsilon.push(s)
          states[e].epsilon.push(cursor)
        }
        Some(max) => {
          for _ in min..<max {
            let (s, e) = compile_expression(child, states)
            states[cursor].epsilon.push(end)
            states[cursor].epsilon.push(s)
            cursor = e
          }
          states[cursor].epsilon.push(end)
        }
      }
    }
  }
  (start, end)
}

///|
fn parse_pattern(text : String, budget : Budget) -> Pattern raise SchemaError {
  if text.length() > 512 || text.iter().any(c => c.to_int() > 127) {
    raise SchemaError("Pattern profile allows at most 512 ASCII characters")
  }
  let parser = { chars: text.to_array(), index: 0, }
  let expression = parser.expression(0)
  if parser.peek() is Some(_) {
    raise SchemaError("Unexpected closing pattern group")
  }
  let states = []
  let (s, e) = compile_expression(expression, states)
  // JSON Schema uses search semantics. The surrounding loops also consume
  // non-ASCII scalars; only the pattern's character atoms are restricted.
  let start = new_state(states)
  let accept = new_state(states)
  states[start].epsilon.push(s)
  states[start].edges.push((0, 0x10ffff, start))
  states[e].epsilon.push(accept)
  states[accept].edges.push((0, 0x10ffff, accept))
  budget.remaining -= text.length() + states.length()
  consume(budget)
  { text, states, start, accept, }
}

///|
fn pattern_close(
  pattern : Pattern,
  seeds : Array[Int32],
  begin : Bool,
  end : Bool,
  budget : Budget,
) -> Array[Int32] raise SchemaError {
  let visited = Array::make(pattern.states.length(), false)
  let stack = seeds.copy()
  let result = []
  while stack.pop() is Some(index) {
    if visited[index] {
      continue
    }
    consume(budget)
    visited[index] = true
    result.push(index)
    let state = pattern.states[index]
    stack.append(state.epsilon)
    if begin {
      stack.append(state.begin)
    }
    if end {
      stack.append(state.end)
    }
  }
  result.sort()
  result
}

///|
fn pattern_move(
  pattern : Pattern,
  states : Array[Int32],
  symbol : Int32,
  budget : Budget,
) -> Array[Int32] raise SchemaError {
  let next = []
  for index in states {
    consume(budget)
    for (low, high, to) in pattern.states[index].edges {
      if symbol >= low && symbol <= high {
        next.push(to)
      }
    }
  }
  pattern_close(pattern, next, false, false, budget)
}

///|
fn pattern_accepts(
  pattern : Pattern,
  value : String,
  budget : Budget,
) -> Bool raise SchemaError {
  let mut states = pattern_close(pattern, [pattern.start], true, false, budget)
  let mut begin = true
  for char in value.iter() {
    states = pattern_move(pattern, states, char.to_int(), budget)
    begin = false
  }
  pattern_close(pattern, states, begin, true, budget).contains(pattern.accept)
}
