///|
/// The two supported OpenAPI document encodings.
pub(all) enum InputFormat {
  Json
  Yaml
} derive(Debug, Eq)

///|
pub extend InputFormat with Debug::{to_repr}

///|
pub extend InputFormat with Eq::{equal, not_equal}

///|
/// A document URI and an RFC 6901 JSON Pointer. No line is fabricated.
pub(all) struct Location {
  uri : String
  pointer : String
} derive(Debug, Eq, ToJson)

///|
pub extend Location with Debug::{to_repr}

///|
pub extend Location with Eq::{equal, not_equal}

///|
pub extend Location with ToJson::{to_json}

///|
pub(all) struct Diagnostic {
  code : String
  message : String
  location : Location
} derive(Debug, Eq, ToJson)

///|
pub extend Diagnostic with Debug::{to_repr}

///|
pub extend Diagnostic with Eq::{equal, not_equal}

///|
pub extend Diagnostic with ToJson::{to_json}

///|
/// A named credential definition with a canonical authentication fingerprint.
pub(all) struct Scheme {
  name : String
  fingerprint : String
  location : Location
} derive(Debug, Eq, ToJson)

///|
pub extend Scheme with Debug::{to_repr}

///|
pub extend Scheme with Eq::{equal, not_equal}

///|
pub extend Scheme with ToJson::{to_json}

///|
/// An operation's effective security, after inheritance and relevant references.
/// `None` means analysis failed; it never represents anonymous access.
pub(all) struct Operation {
  http_method : String
  path : String
  operation_id : String?
  policy : @logic.Policy?
  location : Location
  security_location : Location
  schemes : Array[String]
} derive(Debug)

///|
pub extend Operation with Debug::{to_repr}

///|
pub(all) struct Document {
  source : String
  operations : Array[Operation]
  schemes : Array[Scheme]
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
pub extend Document with Debug::{to_repr}

///|
pub(all) suberror DocumentError {
  DocumentError(String)
} derive(Debug, Eq)

///|
pub extend DocumentError with Debug::{to_repr}

///|
pub extend DocumentError with Eq::{equal, not_equal}

///|
pub fn DocumentError::to_string(self : DocumentError) -> String {
  let DocumentError(message) = self
  message
}

///|
pub impl Show for DocumentError with fn output(self, logger) {
  logger.write_string(self.to_string())
}

///|
pub extend DocumentError with Show::{output}

///|
priv enum Value {
  Null
  Bool(Bool)
  Number
  Str(String)
  Seq(Array[Value])
  Obj(Map[String, Value])
}

///|
priv suberror AuthError {
  AuthError(String, String, String)
}

///|
priv struct Limits {
  mut nodes : Int32
}

///|
priv struct ParsedScheme {
  public_scheme : Scheme
  kind : String
  scopes : Map[String, Bool]
}

///|
priv struct Context {
  root : Value
  source : String
  minor : Int32
  declared : Map[String, Value]
  cache : Map[String, ParsedScheme]
}

///|
fn pointer_key(pointer : String, key : String) -> String {
  pointer +
  "/" +
  key.replace_all(old="~", new="~0").replace_all(old="/", new="~1")
}

///|
fn[V] sorted_keys(obj : Map[String, V]) -> Array[String] {
  let keys = obj.keys().collect()
  keys.sort()
  keys
}

///|
fn issue(
  code : String,
  message : String,
  pointer : String,
) -> Unit raise AuthError {
  raise AuthError(code, message, pointer)
}

///|
fn object(
  value : Value,
  pointer : String,
) -> Map[String, Value] raise AuthError {
  match value {
    Obj(obj) => obj
    _ => {
      issue("auth.type", "Expected an object", pointer)
      abort("unreachable")
    }
  }
}

///|
fn string(value : Value, pointer : String) -> String raise AuthError {
  match value {
    Str(text) => text
    _ => {
      issue("auth.type", "Expected a string", pointer)
      abort("unreachable")
    }
  }
}

///|
fn required_string(
  obj : Map[String, Value],
  key : String,
  pointer : String,
) -> String raise AuthError {
  let location = pointer_key(pointer, key)
  match obj.get(key) {
    Some(value) => {
      let value = string(value, location)
      if value == "" {
        issue("auth.empty", "Required string must not be empty", location)
      }
      value
    }
    None => {
      issue("auth.required", "Missing required field: " + key, location)
      abort("unreachable")
    }
  }
}
