///|
priv struct Bound {
  value : Json
  exclusive : Bool
}

///|
priv struct Bounds {
  lower : Bound?
  upper : Bound?
}

///|
fn empty_bounds() -> Bounds {
  { lower: None, upper: None, }
}

///|
fn bounds_empty(bounds : Bounds) -> Bool {
  bounds.lower is None && bounds.upper is None
}

///|
// Compare decimal strings without converting their coefficients or exponents
// to machine numbers. Exponents such as -1000000000 do not allocate padding.
fn numeric_compare(a : Json, b : Json) -> Int32 {
  let a = decimal(a.stringify())
  let b = decimal(b.stringify())
  if a == b {
    return 0
  }
  let negative_a = a.has_prefix("-")
  let negative_b = b.has_prefix("-")
  if negative_a != negative_b {
    return if negative_a { -1 } else { 1 }
  }
  if a == "0" {
    return if negative_b { 1 } else { -1 }
  }
  if b == "0" {
    return if negative_a { -1 } else { 1 }
  }
  let (ad, ae) = a.split_once("e").unwrap()
  let (bd, be) = b.split_once("e").unwrap()
  let ad = if negative_a { ad[1:] } else { ad }
  let bd = if negative_b { bd[1:] } else { bd }
  let magnitude = (@bigint.BigInt::from_string(ae.to_owned()) +
  @bigint.BigInt::from_int(ad.length())).compare(
    @bigint.BigInt::from_string(be.to_owned()) +
    @bigint.BigInt::from_int(bd.length()),
  )
  let mut result = magnitude
  if result == 0 {
    let length = if ad.length() > bd.length() {
      ad.length()
    } else {
      bd.length()
    }
    for index in 0..<length {
      let ac = if index < ad.length() { ad[index].to_int() } else { 48 }
      let bc = if index < bd.length() { bd[index].to_int() } else { 48 }
      if ac != bc {
        result = ac.compare(bc)
        break
      }
    }
  }
  if negative_a {
    -result
  } else {
    result
  }
}

///|
fn stronger(a : Bound?, b : Bound?, lower : Bool) -> Bound? {
  match (a, b) {
    (None, _) => b
    (_, None) => a
    (Some(a), Some(b)) => {
      let cmp = numeric_compare(a.value, b.value)
      if (lower && cmp > 0) || (!lower && cmp < 0) {
        Some(a)
      } else if cmp == 0 {
        Some({ value: a.value, exclusive: a.exclusive || b.exclusive, })
      } else {
        Some(b)
      }
    }
  }
}

///|
fn merge_bounds(a : Bounds, b : Bounds) -> Bounds {
  {
    lower: stronger(a.lower, b.lower, true),
    upper: stronger(a.upper, b.upper, false),
  }
}

///|
fn bound_number(
  fields : Map[String, Json],
  key : String,
) -> Bound? raise SchemaError {
  match fields.get(key) {
    None => None
    Some(value) if value is Number(_) => Some({ value, exclusive: false, })
    _ => raise SchemaError(key + " must be a number")
  }
}

///|
fn read_numeric(
  fields : Map[String, Json],
  legacy : Bool,
) -> Bounds raise SchemaError {
  let mut lower = bound_number(fields, "minimum")
  let mut upper = bound_number(fields, "maximum")
  for
    (key, is_lower) in [("exclusiveMinimum", true), ("exclusiveMaximum", false)] {
    if fields.get(key) is Some(value) {
      let selected = if is_lower { lower } else { upper }
      let exclusive = if legacy {
        match value {
          False => selected
          True =>
            match selected {
              Some(bound) => Some({ ..bound, exclusive: true, })
              None =>
                raise SchemaError(
                  key + " requires its corresponding bound in OpenAPI 3.0",
                )
            }
          _ => raise SchemaError(key + " must be a boolean in OpenAPI 3.0")
        }
      } else {
        if !(value is Number(_)) {
          raise SchemaError(key + " must be a number in OpenAPI 3.1")
        }
        stronger(selected, Some({ value, exclusive: true, }), is_lower)
      }
      if is_lower {
        lower = exclusive
      } else {
        upper = exclusive
      }
    }
  }
  { lower, upper, }
}

///|
fn read_size(
  fields : Map[String, Json],
  min : String,
  max : String,
) -> Bounds raise SchemaError {
  let lower = bound_number(fields, min)
  let upper = bound_number(fields, max)
  for bound in [lower, upper] {
    if bound is Some(bound) &&
      (
        kind(bound.value) != "integer" ||
        numeric_compare(bound.value, Json::number(0)) < 0
      ) {
      raise SchemaError("Size bounds must be nonnegative integers")
    }
  }
  {
    lower: match lower {
      Some(bound) if numeric_compare(bound.value, Json::number(0)) == 0 => None
      _ => lower
    },
    upper,
  }
}

///|
fn within(bounds : Bounds, value : Json) -> Bool {
  if bounds.lower is Some(bound) {
    let cmp = numeric_compare(value, bound.value)
    if cmp < 0 || (cmp == 0 && bound.exclusive) {
      return false
    }
  }
  if bounds.upper is Some(bound) {
    let cmp = numeric_compare(value, bound.value)
    if cmp > 0 || (cmp == 0 && bound.exclusive) {
      return false
    }
  }
  true
}

///|
fn bounds_imply(a : Bounds, b : Bounds) -> Bool {
  for
    (source, target, lower) in [
      (a.lower, b.lower, true),
      (a.upper, b.upper, false),
    ] {
    if target is Some(target) {
      match source {
        None => return false
        Some(source) => {
          let cmp = numeric_compare(source.value, target.value)
          if (lower && cmp < 0) ||
            (!lower && cmp > 0) ||
            (cmp == 0 && target.exclusive && !source.exclusive) {
            return false
          }
        }
      }
    }
  }
  true
}

///|
fn integer_bounds(bounds : Bounds) -> Bounds {
  let converted = []
  for (bound, lower) in [(bounds.lower, true), (bounds.upper, false)] {
    let next = match bound {
      None => None
      Some(bound) => {
        let key = decimal(bound.value.stringify())
        let (coefficient, power) = if key == "0" {
          ("0", "0")
        } else {
          let (c, e) = key.split_once("e").unwrap()
          (c.to_owned(), e.to_owned())
        }
        let c = @bigint.BigInt::from_string(coefficient)
        let e = @bigint.BigInt::from_string(power)
        let zero = @bigint.BigInt::from_int(0)
        let one = @bigint.BigInt::from_int(1)
        if coefficient.length() > 4096 ||
          e > @bigint.BigInt::from_int(4096 - coefficient.length()) {
          Some(bound)
        } else {
          let mut integer = c
          let mut fractional = false
          if e < zero {
            if -e >= @bigint.BigInt::from_int(coefficient.length()) {
              integer = zero
              fractional = c != zero
            } else {
              let scale = @bigint.BigInt::from_int(10).pow(-e)
              integer = c / scale
              fractional = c % scale != zero
            }
          } else {
            integer = c * @bigint.BigInt::from_int(10).pow(e)
          }
          if lower {
            if fractional {
              if c > zero {
                integer += one
              }
            } else if bound.exclusive {
              integer += one
            }
          } else if fractional {
            if c < zero {
              integer -= one
            }
          } else if bound.exclusive {
            integer -= one
          }
          try {
            let value = @json.parse(
              integer.to_string(),
              preserve_number_repr=true,
            )
            if value is Number(n, ..) &&
              n <= 1.7976931348623157e308 &&
              n >= -1.7976931348623157e308 {
              Some({ value, exclusive: false, })
            } else {
              Some(bound)
            }
          } catch {
            _ => Some(bound)
          }
        }
      }
    }
    converted.push(next)
  }
  { lower: converted[0], upper: converted[1], }
}

///|
fn bounds_key(bounds : Bounds) -> Json {
  Json::array(
    [bounds.lower, bounds.upper].map(b => {
      match b {
        None => Json::null()
        Some(b) =>
          Json::array([
            Json::string(identity(b.value)),
            Json::boolean(b.exclusive),
          ])
      }
    }),
  )
}

///|
// Neighbours are exact decimals; each is checked by the independent evaluator.
// Construct at most 4096 coefficient digits, independent of exponent magnitude.
fn numeric_candidates(bounds : Bounds) -> Array[Json] {
  let result = [
    Json::number(0),
    Json::number(1),
    Json::number(-1),
    Json::number(0.5),
  ]
  for bound in [bounds.lower, bounds.upper] {
    if bound is Some(bound) {
      result.push(bound.value)
      let key = decimal(bound.value.stringify())
      let (coefficient, power) = if key == "0" {
        ("0", "0")
      } else {
        let (c, p) = key.split_once("e").unwrap()
        (c.to_owned(), p.to_owned())
      }
      if coefficient.length() > 4096 {
        continue
      }
      let c = @bigint.BigInt::from_string(coefficient)
      let e = @bigint.BigInt::from_string(power)
      for step in [-1, 1] {
        // An integer neighbour and a finer decimal neighbour cover integer and
        // dense numeric intervals without floating point epsilon arithmetic.
        for
          (c, e) in [
            (c + @bigint.BigInt::from_int(step), e),
            (
              c * @bigint.BigInt::from_int(10) + @bigint.BigInt::from_int(step),
              e - @bigint.BigInt::from_int(1),
            ),
          ] {
          let parsed = @json.parse(
            c.to_string() + "e" + e.to_string(),
            preserve_number_repr=true,
          ) catch {
            _ => continue
          }
          if parsed is Number(n, ..) &&
            n == n &&
            n <= 1.7976931348623157e308 &&
            n >= -1.7976931348623157e308 {
            result.push(parsed)
          }
        }
      }
      // Round fractional boundaries toward nearby integers when tractable.
      if e < @bigint.BigInt::from_int(0) && e >= @bigint.BigInt::from_int(-4096) {
        let scale = @bigint.BigInt::from_int(10).pow(-e)
        let integer = c / scale
        for step in [-1, 0, 1] {
          let parsed = @json.parse(
            (integer + @bigint.BigInt::from_int(step)).to_string(),
            preserve_number_repr=true,
          ) catch {
            _ => continue
          }
          if parsed is Number(n, ..) &&
            n <= 1.7976931348623157e308 &&
            n >= -1.7976931348623157e308 {
            result.push(parsed)
          }
        }
      }
    }
  }
  result
}

///|
fn size_candidates(bounds : Bounds) -> Array[Int32] {
  let result = [0, 1]
  for value in numeric_candidates(bounds) {
    if value is Number(n, ..) && n >= 0 && n <= 4096 && kind(value) == "integer" {
      let size = n.to_int()
      if !result.contains(size) {
        result.push(size)
      }
    }
  }
  result
}

///|
fn sized_string(size : Int32) -> Json {
  let out = StringBuilder()
  for _ in 0..<size {
    out.write_string("a")
  }
  Json::string(out.to_string())
}

///|
fn scalar_samples(
  rule : Constraints,
  kind : String,
  budget : Budget,
) -> Array[Json] raise SchemaError {
  consume(budget)
  if kind == "integer" || kind == "number" {
    return numeric_candidates(rule.numeric)
  }
  if kind == "string" {
    return size_candidates(rule.length).map(sized_string)
  }
  let result = []
  if kind == "array" {
    for size in size_candidates(rule.size) {
      consume(budget)
      if size == 0 {
        result.push(Json::array([]))
      } else if sample(rule.items, budget) is Some(value) {
        result.push(Json::array(Array::make(size, value)))
      }
    }
  } else if kind == "object" {
    for size in size_candidates(rule.count) {
      let fields = Map([])
      let mut valid = true
      for key in rule.required {
        match
          sample(rule.properties.get(key).unwrap_or(rule.additional), budget) {
          Some(value) => fields[key] = value
          None => valid = false
        }
      }
      let keys = rule.properties.keys().collect()
      keys.sort()
      for key in keys {
        if fields.length() >= size {
          break
        }
        if !fields.contains(key) &&
          sample(rule.properties[key], budget) is Some(value) {
          fields[key] = value
        }
      }
      let mut index = 0
      while fields.length() < size {
        consume(budget)
        let key = "additional" + index.to_string()
        index += 1
        if rule.properties.contains(key) || fields.contains(key) {
          continue
        }
        match sample(rule.additional, budget) {
          Some(value) => fields[key] = value
          None => {
            valid = false
            break
          }
        }
      }
      if valid {
        result.push(Json::object(fields))
      }
    }
  }
  result
}
