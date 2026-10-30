///|
// Accepted JSON and YAML decimal scalars have a finite significand/exponent.
// Normalize their decimal spelling without comparing rounded Double values.
fn decimal_key(text : String) -> String {
  let parts = text.to_lower().split_once("e")
  let (mantissa, exponent) = match parts {
    Some((mantissa, exponent)) => (mantissa.to_owned(), exponent.to_owned())
    None => (text, "0")
  }
  let negative = mantissa.has_prefix("-")
  let mantissa = if negative || mantissa.has_prefix("+") {
    mantissa[1:].to_owned()
  } else {
    mantissa
  }
  let fraction = match mantissa.split_once(".") {
    Some((_, tail)) => tail.length()
    None => 0
  }
  let digits = mantissa.replace_all(old=".", new="")
  let mut first = 0
  while first < digits.length() && digits[first] == '0' {
    first += 1
  }
  if first == digits.length() {
    return "0"
  }
  let mut end = digits.length()
  while end > first && digits[end - 1] == '0' {
    end -= 1
  }
  let exponent = if exponent.has_prefix("+") {
    exponent[1:].to_owned()
  } else {
    exponent
  }
  let power = @bigint.BigInt::from_string(exponent) +
    @bigint.BigInt::from_string((digits.length() - end - fraction).to_string())
  (if negative { "-" } else { "" }) +
  digits[first:end].to_owned() +
  "e" +
  power.to_string()
}

///|
fn yaml_number(text : String, value : Double) -> Json {
  let negative = text.has_prefix("-")
  let unsigned = if negative || text.has_prefix("+") {
    text[1:].to_owned()
  } else {
    text
  }
  let lower = unsigned.to_lower()
  let literal = if lower.has_prefix("0x") || lower.has_prefix("0o") {
    let radix = if lower.has_prefix("0x") { 16 } else { 8 }
    (if negative { "-" } else { "" }) +
    @bigint.BigInt::from_string(unsigned[2:].to_owned(), radix~).to_string()
  } else {
    decimal_key(text)
  }
  Json::number(value, repr=literal)
}

///|
fn value_json(value : Value) -> Json {
  match value {
    Null => Json::null()
    Bool(value) => Json::boolean(value)
    Number(value) => value
    Str(value) => Json::string(value)
    Seq(items) => Json::array(items.map(value_json))
    Obj(fields) => {
      let result = Map([])
      for (key, value) in fields {
        result[key] = value_json(value)
      }
      Json::object(result)
    }
  }
}
