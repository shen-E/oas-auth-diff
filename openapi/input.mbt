///|
fn Limits::charge(self : Limits, pointer : String) -> Unit raise DocumentError {
  self.nodes += 1
  if self.nodes > self.maximum {
    let message = if self.maximum < 250000 {
      "Input exceeds remaining aggregate node budget at #"
    } else {
      "Input exceeds 250000 nodes at #"
    }
    raise DocumentError(message + pointer)
  }
}

///|
fn finite(value : Double) -> Bool {
  value == value &&
  value <= 1.7976931348623157e308 &&
  value >= -1.7976931348623157e308
}

///|
fn from_json(
  value : Json,
  limits : Limits,
  pointer : String,
) -> Value raise DocumentError {
  limits.charge(pointer)
  match value {
    Null => Null
    True => Bool(true)
    False => Bool(false)
    Number(number, ..) => {
      if !finite(number) {
        raise DocumentError("Non-finite number at #" + pointer)
      }
      Number
    }
    String(text) => Str(text)
    Array(items) => {
      let out = []
      for index, item in items {
        out.push(
          from_json(item, limits, pointer_key(pointer, index.to_string())),
        )
      }
      Seq(out)
    }
    Object(obj) => {
      let out = Map([])
      for key, value in obj {
        let location = pointer_key(pointer, key)
        limits.charge(location)
        out[key] = from_json(value, limits, location)
      }
      Obj(out)
    }
  }
}

///|
fn yaml_resolve(
  text : String,
  quoted : Bool,
  tag : String?,
  at : @yaml.At,
  rules : @yaml.Rules,
) -> Json raise @yaml.Refused {
  let value = (@yaml.core.resolve)(text, quoted, tag, at, rules)
  if value is Number(number, ..) && !finite(number) {
    raise @yaml.Disallowed(at, "a non-finite number")
  }
  value
}

///|
fn from_yaml(
  node : @yaml.Node,
  limits : Limits,
  pointer : String,
) -> Value raise DocumentError {
  limits.charge(pointer)
  match node.kind {
    Null => Null
    Bool(value) => Bool(value)
    Number(value) => {
      if !finite(value) {
        raise DocumentError("Non-finite number at #" + pointer)
      }
      Number
    }
    Str(value) => Str(value)
    Sequence(items) => {
      let out = []
      for index, item in items {
        out.push(
          from_yaml(item, limits, pointer_key(pointer, index.to_string())),
        )
      }
      Seq(out)
    }
    Mapping(entries) => {
      let out = Map([])
      for (key_node, value) in entries {
        let key = match key_node.kind {
          Str(key) => key
          _ =>
            raise DocumentError(
              "YAML mapping key must be a string at #" + pointer,
            )
        }
        let location = pointer_key(pointer, key)
        limits.charge(location)
        if key == "<<" && key_node.style == @yaml.Plain {
          raise DocumentError("YAML merge keys are disabled at #" + location)
        }
        if out.contains(key) {
          raise DocumentError("Duplicate YAML key at #" + location)
        }
        out[key] = from_yaml(value, limits, location)
      }
      Obj(out)
    }
    Alias(_) => raise DocumentError("YAML aliases are disabled at #" + pointer)
  }
}

///|
fn read_input(
  text : String,
  format : InputFormat,
  node_limit~ : Int32 = 250000,
) -> (Value, Int32) raise DocumentError {
  if @utf8.encode(text).length() > 16 * 1024 * 1024 {
    raise DocumentError("Input exceeds 16 MiB")
  }
  let limits = { nodes: 0, maximum: node_limit, }
  let root = match format {
    Json => {
      let parsed = @json.parse(
        text,
        reject_duplicate_keys=true,
        max_nesting_depth=128,
        preserve_number_repr=true,
      ) catch {
        error => raise DocumentError(error.to_string())
      }
      from_json(parsed, limits, "")
    }
    Yaml => {
      if @yaml.declared_version(text) is Some(version) && version != (1, 2) {
        raise DocumentError("Only YAML 1.2 directives are supported")
      }
      let schema = {
        ..@yaml.core,
        resolve: yaml_resolve,
        tags: false,
        anchors: false,
        merge: false,
      }
      let docs = @yaml.parse_all(
        text,
        flavor=@yaml.Flavor::new(
          depth=128,
          duplicates=@yaml.Reject,
          aliases=false,
          budget=node_limit,
        ),
        schema~,
      ) catch {
        error => {
          if node_limit < 250000 && error is @yaml.Exceeded(..) {
            raise DocumentError(
              "Input exceeds remaining aggregate node budget at " +
              error.at().to_string(),
            )
          }
          raise DocumentError(error.to_string())
        }
      }
      if docs.length() != 1 {
        raise DocumentError("Expected exactly one YAML document")
      }
      from_yaml(docs[0], limits, "")
    }
  }
  (root, limits.nodes)
}
