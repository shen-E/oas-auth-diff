///|
// Intersect every property with the other branch's actual additionalProperties
// rule. Copying only named properties would change allOf on closed objects.
fn intersect(a : Model, b : Model, budget : Budget) -> Model raise SchemaError {
  consume(budget)
  match (a, b) {
    (Never, _) | (_, Never) => Never
    (Any, _) => b
    (_, Any) => a
    (Rule(a), Rule(b)) => {
      let types = a.types.filter(t => b.types.contains(t))
      if types.is_empty() {
        return Never
      }
      let properties = Map([])
      for (key, child) in a.properties {
        properties[key] = intersect(
          child,
          b.properties.get(key).unwrap_or(b.additional),
          budget,
        )
      }
      for (key, child) in b.properties {
        if !a.properties.contains(key) {
          properties[key] = intersect(a.additional, child, budget)
        }
      }
      let required = a.required.copy()
      for key in b.required {
        if !required.contains(key) {
          required.push(key)
        }
      }
      let values = match (a.values, b.values) {
        (Some(a), Some(b)) => {
          let allowed = Map([])
          for value in b {
            consume(budget)
            allowed[identity(value)] = true
          }
          let selected = []
          for value in a {
            consume(budget)
            if allowed.contains(identity(value)) {
              selected.push(value)
            }
          }
          Some(selected)
        }
        (Some(a), None) => Some(a)
        (None, Some(b)) => Some(b)
        _ => None
      }
      Rule({
        types,
        values,
        properties,
        required,
        additional: intersect(a.additional, b.additional, budget),
        items: intersect(a.items, b.items, budget),
        numeric: merge_bounds(a.numeric, b.numeric),
        length: merge_bounds(a.length, b.length),
        size: merge_bounds(a.size, b.size),
        count: merge_bounds(a.count, b.count),
        patterns: {
          let patterns = a.patterns.copy()
          for p in b.patterns {
            if !patterns.any(q => p.text == q.text) {
              patterns.push(p)
            }
          }
          patterns
        },
      })
    }
    (All(children), _) => {
      let all = children.copy()
      all.push(b)
      All(all)
    }
    (_, All(children)) => {
      let all = [a]
      all.append(children)
      All(all)
    }
    _ => All([a, b])
  }
}

///|
fn model_key(model : Model, budget : Budget) -> String raise SchemaError {
  consume(budget)
  match model {
    Any => "true"
    Never => "false"
    Rule(rule) => {
      let types = rule.types.copy()
      types.sort()
      let required = rule.required.copy()
      required.sort()
      let properties = Map([])
      for (key, child) in rule.properties {
        properties[key] = Json::string(model_key(child, budget))
      }
      let values = match rule.values {
        None => Json::null()
        Some(values) => {
          let keys = values.map(identity)
          keys.sort()
          Json(keys)
        }
      }
      let key : Json = {
        "types": Json(types),
        "required": Json(required),
        "enum": values,
        "properties": Json::object(properties),
        "additional": model_key(rule.additional, budget),
        "items": model_key(rule.items, budget),
        "numeric": bounds_key(rule.numeric),
        "length": bounds_key(rule.length),
        "size": bounds_key(rule.size),
        "count": bounds_key(rule.count),
        "patterns": {
          let texts = rule.patterns.map(p => p.text)
          texts.sort()
          Json(texts)
        },
      }
      identity(key)
    }
    All(children) | Union(children) | ExactlyOne(children) => {
      let keys = []
      for child in children {
        keys.push(model_key(child, budget))
      }
      keys.sort()
      let tag = match model {
        All(_) => "all"
        Union(_) => "any"
        _ => "one"
      }
      tag + Json(keys).stringify()
    }
  }
}

///|
// Some means this finite collection covers every possible accepted instance.
// Filtering below uses the evaluator and preserves exactly-one overlap semantics.
fn finite_values(
  model : Model,
  budget : Budget,
) -> Array[Json]? raise SchemaError {
  consume(budget)
  let candidates = match model {
    Never => []
    Rule(rule) =>
      match rule.values {
        Some(values) => values
        None => return None
      }
    Any => return None
    All(children) => {
      let mut finite = None
      for child in children {
        if finite_values(child, budget) is Some(values) {
          finite = Some(values)
          break
        }
      }
      match finite {
        Some(values) => values
        None => return None
      }
    }
    Union(children) | ExactlyOne(children) => {
      let collected = []
      for child in children {
        match finite_values(child, budget) {
          Some(values) => collected.append(values)
          None => return None
        }
      }
      collected
    }
  }
  let result = []
  let seen = Map([])
  for value in candidates {
    consume(budget)
    let key = identity(value)
    if !seen.contains(key) && accepts_model(model, value, budget) {
      result.push(value)
      seen[key] = true
    }
  }
  Some(result)
}

///|
fn disjoint(a : Model, b : Model, budget : Budget) -> Bool raise SchemaError {
  consume(budget)
  if finite_values(a, budget) is Some(values) {
    for value in values {
      if accepts_model(b, value, budget) {
        return false
      }
    }
    return true
  }
  if finite_values(b, budget) is Some(values) {
    for value in values {
      if accepts_model(a, value, budget) {
        return false
      }
    }
    return true
  }
  match (a, b) {
    (Rule(a), Rule(b)) => {
      let common = a.types.filter(t => b.types.contains(t))
      if common.is_empty() {
        return true
      }
      if common == ["object"] {
        for key in a.required {
          if b.required.contains(key) &&
            disjoint(
              a.properties.get(key).unwrap_or(a.additional),
              b.properties.get(key).unwrap_or(b.additional),
              budget,
            ) {
            return true
          }
        }
      }
      false
    }
    (All(children), _) => {
      for child in children {
        if disjoint(child, b, budget) {
          return true
        }
      }
      false
    }
    (_, All(children)) => {
      for child in children {
        if disjoint(a, child, budget) {
          return true
        }
      }
      false
    }
    (Union(children), _) | (ExactlyOne(children), _) => {
      for child in children {
        if !disjoint(child, b, budget) {
          return false
        }
      }
      true
    }
    (_, Union(children)) | (_, ExactlyOne(children)) => {
      for child in children {
        if !disjoint(a, child, budget) {
          return false
        }
      }
      true
    }
    _ => false
  }
}
