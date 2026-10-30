///|
// core/string's regex parser requires literal hyphens to be escaped even at
// the first/last position of a character class. The official schemas use the
// equivalent ECMA-262 spelling without an escape in those positions.
fn compatible_pattern(pattern : String) -> String {
  let out = StringBuilder()
  let mut in_class = false
  let mut first = false
  let mut escaped = false
  let chars = pattern.to_array()
  for index in 0..<chars.length() {
    let char = chars[index]
    if escaped {
      out.write_char(char)
      escaped = false
      first = false
      continue
    }
    if char == '\\' {
      out.write_char(char)
      escaped = true
      continue
    }
    if char == '[' && !in_class {
      in_class = true
      first = true
    } else if char == ']' {
      in_class = false
    } else if in_class {
      if char == '-' &&
        (first || (index + 1 < chars.length() && chars[index + 1] == ']')) {
        out.write_char('\\')
      }
      if char != '^' || !first {
        first = false
      }
    }
    out.write_char(char)
  }
  out.to_string()
}

///|
fn engine_schema(value : Json) -> Json {
  match value {
    Object(fields) => {
      let result = Map([])
      for (key, child) in fields {
        result[key] = match child {
          String(pattern) if key == "pattern" =>
            Json::string(compatible_pattern(pattern))
          _ => engine_schema(child)
        }
      }
      Json::object(result)
    }
    Array(values) => Json::array(values.map(engine_schema))
    _ => value
  }
}
