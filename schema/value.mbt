///|
// Decimal equality must not round adjacent large integers through Double.
fn decimal(text : String) -> String {
  let (mantissa, exponent) = match text.to_lower().split_once("e") {
    Some((m, e)) => (m.to_owned(), e.to_owned())
    None => (text, "0")
  }
  let negative = mantissa.has_prefix("-")
  let mantissa = if negative { mantissa[1:].to_owned() } else { mantissa }
  let fraction = match mantissa.split_once(".") {
    Some((_, tail)) => tail.length()
    None => 0
  }
  let digits = mantissa.replace_all(old=".", new="")
  let mut start = 0
  while start < digits.length() && digits[start] == '0' {
    start += 1
  }
  if start == digits.length() {
    return "0"
  }
  let mut end = digits.length()
  while end > start && digits[end - 1] == '0' {
    end -= 1
  }
  let exponent = if exponent.has_prefix("+") {
    exponent[1:].to_owned()
  } else {
    exponent
  }
  let power = @bigint.BigInt::from_string(exponent) +
    @bigint.BigInt::from_int(digits.length() - end - fraction)
  (if negative { "-" } else { "" }) +
  digits[start:end].to_owned() +
  "e" +
  power.to_string()
}

///|
fn identity(value : Json) -> String {
  match value {
    Object(fields) => {
      let keys = fields.keys().collect()
      keys.sort()
      "{" +
      keys
      .map(k => Json::string(k).stringify() + ":" + identity(fields[k]))
      .join(",") +
      "}"
    }
    Array(values) => "[" + values.map(identity).join(",") + "]"
    Number(_) => decimal(value.stringify())
    _ => value.stringify()
  }
}

///|
fn copy_value(value : Json) -> Json {
  match value {
    Object(fields) => {
      let copied = Map([])
      for (key, value) in fields {
        copied[key] = copy_value(value)
      }
      Json::object(copied)
    }
    Array(values) => Json::array(values.map(copy_value))
    _ => value
  }
}

///|
fn kind(value : Json) -> String {
  match value {
    Null => "null"
    True | False => "boolean"
    String(_) => "string"
    Array(_) => "array"
    Object(_) => "object"
    Number(_) => {
      let key = decimal(value.stringify())
      if key == "0" {
        return "integer"
      }
      let exponent = key.split_once("e").unwrap().1.to_owned()
      if exponent.has_prefix("-") {
        "number"
      } else {
        "integer"
      }
    }
  }
}

///|
fn accepts_model(
  model : Model,
  value : Json,
  budget : Budget,
) -> Bool raise SchemaError {
  consume(budget)
  match model {
    Any => true
    Never => false
    All(children) => {
      for child in children {
        if !accepts_model(child, value, budget) {
          return false
        }
      }
      true
    }
    Union(children) => {
      for child in children {
        if accepts_model(child, value, budget) {
          return true
        }
      }
      false
    }
    ExactlyOne(children) => {
      let mut matches = 0
      for child in children {
        if accepts_model(child, value, budget) {
          matches += 1
          if matches > 1 {
            return false
          }
        }
      }
      matches == 1
    }
    Rule(rule) => {
      if !rule.types.contains(kind(value)) {
        return false
      }
      if rule.values is Some(values) {
        let mut found = false
        let key = identity(value)
        for candidate in values {
          consume(budget)
          if identity(candidate) == key {
            found = true
            break
          }
        }
        if !found {
          return false
        }
      }
      match value {
        Object(fields) => {
          if rule.required.any(k => !fields.contains(k)) {
            return false
          }
          for (key, child) in fields {
            if !accepts_model(
                rule.properties.get(key).unwrap_or(rule.additional),
                child,
                budget,
              ) {
              return false
            }
          }
          true
        }
        Array(values) => {
          for value in values {
            if !accepts_model(rule.items, value, budget) {
              return false
            }
          }
          true
        }
        _ => true
      }
    }
  }
}

///|
/// Independently evaluate an instance without using the inclusion algorithm.
pub fn Schema::accepts(self : Schema, value : Json) -> Bool raise SchemaError {
  validate_value(value, 0, { remaining: 20000, })
  accepts_model(self.model, value, { remaining: 20000, })
}
