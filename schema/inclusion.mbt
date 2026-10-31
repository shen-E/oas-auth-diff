///|
fn implies(a : Model, b : Model, budget : Budget) -> Bool raise SchemaError {
  consume(budget)
  if model_key(a, budget) == model_key(b, budget) {
    return true
  }
  if finite_values(a, budget) is Some(values) {
    for value in values {
      if !accepts_model(b, value, budget) {
        return false
      }
    }
    return true
  }
  match (a, b) {
    (_, Any) | (Never, _) => true
    (Union(children), _) | (ExactlyOne(children), _) => {
      for child in children {
        if !implies(child, b, budget) {
          return false
        }
      }
      true
    }
    (_, All(children)) => {
      for child in children {
        if !implies(a, child, budget) {
          return false
        }
      }
      true
    }
    (All(children), _) => {
      for child in children {
        if implies(child, b, budget) {
          return true
        }
      }
      false
    }
    (_, Union(children)) => {
      if a is Rule(rule) && rule.types.length() > 1 {
        let mut covered = true
        for kind in rule.types {
          if !implies(Rule({ ..rule, types: [kind], }), b, budget) {
            covered = false
            break
          }
        }
        if covered {
          return true
        }
      }
      for child in children {
        if implies(a, child, budget) {
          return true
        }
      }
      false
    }
    (_, ExactlyOne(children)) => {
      if a is Rule(rule) && rule.types.length() > 1 {
        let mut covered = true
        for kind in rule.types {
          if !implies(Rule({ ..rule, types: [kind], }), b, budget) {
            covered = false
            break
          }
        }
        if covered {
          return true
        }
      }
      for index, child in children {
        if implies(a, child, budget) {
          let mut exclusive = true
          for other_index, other in children {
            if index != other_index && !disjoint(a, other, budget) {
              exclusive = false
              break
            }
          }
          if exclusive {
            return true
          }
        }
      }
      false
    }
    (Rule(a), _) if a.values is Some(values) => {
      for value in values {
        if accepts_model(Rule(a), value, budget) &&
          !accepts_model(b, value, budget) {
          return false
        }
      }
      true
    }
    (Rule(a), Rule(b)) => {
      if a.types.any(t => !b.types.contains(t)) || b.values is Some(_) {
        return false
      }
      if a.types.contains("number") && !bounds_imply(a.numeric, b.numeric) {
        return false
      }
      if a.types.contains("integer") &&
        !bounds_imply(integer_bounds(a.numeric), integer_bounds(b.numeric)) {
        return false
      }
      if a.types.contains("string") && !bounds_imply(a.length, b.length) {
        return false
      }
      if a.types.contains("array") && !bounds_imply(a.size, b.size) {
        return false
      }
      if a.types.contains("object") {
        if !bounds_imply(a.count, b.count) {
          return false
        }
        if b.required.any(k => !a.required.contains(k)) {
          return false
        }
        for (key, child) in b.properties {
          if !implies(
              a.properties.get(key).unwrap_or(a.additional),
              child,
              budget,
            ) {
            return false
          }
        }
        for (key, child) in a.properties {
          if !b.properties.contains(key) &&
            !implies(child, b.additional, budget) {
            return false
          }
        }
        if !implies(a.additional, b.additional, budget) {
          return false
        }
      }
      !a.types.contains("array") || implies(a.items, b.items, budget)
    }
    _ => false
  }
}

///|
fn sample(model : Model, budget : Budget) -> Json? raise SchemaError {
  consume(budget)
  match model {
    Any => Some(Json::null())
    Never => None
    All(children) | Union(children) | ExactlyOne(children) => {
      if finite_values(model, budget) is Some(values) {
        return values.get(0)
      }
      for child in children {
        if sample(child, budget) is Some(value) &&
          accepts_model(model, value, budget) {
          return Some(value)
        }
      }
      None
    }
    Rule(rule) => {
      if rule.values is Some(values) {
        for value in values {
          if accepts_model(model, value, budget) {
            return Some(value)
          }
        }
        return None
      }
      for kind in rule.types {
        let value = match kind {
          "object" | "array" | "string" | "integer" | "number" => {
            for value in scalar_samples(rule, kind, budget) {
              if accepts_model(model, value, budget) {
                return Some(value)
              }
            }
            continue
          }
          "boolean" => Json::boolean(false)
          _ => Json::null()
        }
        if accepts_model(model, value, budget) {
          return Some(value)
        }
      }
      None
    }
  }
}

///|
fn constraints(model : Model) -> Constraints {
  match model {
    Rule(rule) => rule
    Any | All(_) | Union(_) | ExactlyOne(_) =>
      {
        types: kinds,
        values: None,
        properties: Map([]),
        required: [],
        additional: Any,
        items: Any,
        numeric: empty_bounds(),
        length: empty_bounds(),
        size: empty_bounds(),
        count: empty_bounds(),
      }
    Never =>
      {
        types: [],
        values: None,
        properties: Map([]),
        required: [],
        additional: Never,
        items: Never,
        numeric: empty_bounds(),
        length: empty_bounds(),
        size: empty_bounds(),
        count: empty_bounds(),
      }
  }
}

///|
fn counterexample(
  a : Model,
  b : Model,
  budget : Budget,
) -> Json? raise SchemaError {
  consume(budget)
  if implies(a, b, budget) {
    return None
  }
  let candidates = []
  if finite_values(a, budget) is Some(values) {
    candidates.append(values)
  }
  match a {
    All(children) | Union(children) | ExactlyOne(children) =>
      for child in children {
        if counterexample(child, b, budget) is Some(value) {
          candidates.push(value)
        }
      }
    _ => ()
  }
  match b {
    All(children) | Union(children) | ExactlyOne(children) =>
      for child in children {
        if counterexample(a, child, budget) is Some(value) {
          candidates.push(value)
        }
      }
    _ => ()
  }
  if sample(a, budget) is Some(value) {
    candidates.push(value)
  }
  let left = constraints(a)
  let right = constraints(b)
  candidates.append(numeric_candidates(left.numeric))
  candidates.append(numeric_candidates(right.numeric))
  for kind in ["string", "array", "object"] {
    candidates.append(scalar_samples(left, kind, budget))
    let mixed = match kind {
      "string" => { ..left, length: right.length, }
      "array" => { ..left, size: right.size, }
      _ => { ..left, count: right.count, }
    }
    candidates.append(scalar_samples(mixed, kind, budget))
  }
  if left.values is Some(values) {
    candidates.append(values)
  }
  candidates.append([
    Json::null(),
    Json::boolean(false),
    Json::boolean(true),
    Json::number(0),
    Json::number(0.5),
    Json::string(""),
    Json::array([]),
    Json::object(Map([])),
  ])
  // A finite target enum can never cover all strings or all integers.
  let attempts = match right.values {
    Some(values) => values.length() + 1
    None => 1
  }
  for index in 0..<(if attempts < 1024 { attempts } else { 1024 }) {
    candidates.push(Json::string("witness" + index.to_string()))
    candidates.push(Json::number(index.to_double()))
  }
  for value in candidates {
    if accepts_model(a, value, budget) && !accepts_model(b, value, budget) {
      return Some(value)
    }
  }
  candidates.clear()
  if left.types.contains("object") {
    let object_model = Rule({ ..left, types: ["object"], })
    if sample(object_model, budget) is Some(Object(base)) {
      let keys = left.properties.keys().collect()
      for key in right.properties.keys() {
        if !keys.contains(key) {
          keys.push(key)
        }
      }
      for key in right.required {
        if !keys.contains(key) {
          keys.push(key)
        }
      }
      let mut extra = "additional"
      while keys.contains(extra) {
        extra += "_"
      }
      keys.push(extra)
      for key in keys {
        let child = counterexample(
          left.properties.get(key).unwrap_or(left.additional),
          right.properties.get(key).unwrap_or(right.additional),
          budget,
        )
        if child is Some(value) {
          let fields = base.copy()
          fields[key] = value
          candidates.push(Json::object(fields))
        }
      }
    }
  }
  if left.types.contains("array") && !(left.items is Any && right.items is Any) {
    if counterexample(left.items, right.items, budget) is Some(value) {
      for size in size_candidates(left.size) {
        if size > 0 {
          candidates.push(Json::array(Array::make(size, value)))
        }
      }
    }
  }
  for value in candidates {
    if accepts_model(a, value, budget) && !accepts_model(b, value, budget) {
      return Some(value)
    }
  }
  None
}

///|
/// Decide whether every source instance is also a target instance.
/// Proof failure without a validated counterexample returns Unknown.
pub fn subset(source : Schema, target : Schema) -> Inclusion {
  try {
    let budget = { remaining: 20000, }
    if implies(source.model, target.model, budget) {
      return Included
    }
    match counterexample(source.model, target.model, budget) {
      Some(value) if source.accepts(value) && !target.accepts(value) =>
        Excluded(copy_value(value))
      _ =>
        Unknown(
          "No inclusion proof or validated counterexample within the supported Schema fragment",
        )
    }
  } catch {
    SchemaError(message) => Unknown(message)
  }
}
