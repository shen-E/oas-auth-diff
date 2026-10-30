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
/// One independently encoded source returned by a local document loader.
/// `source` is its canonical identity, used for locations, caching and cycles.
pub(all) struct SourceDocument {
  text : String
  format : InputFormat
  source : String
} derive(Debug, Eq)

///|
pub extend SourceDocument with Debug::{to_repr}

///|
pub extend SourceDocument with Eq::{equal, not_equal}

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
/// A named credential fingerprint. Operation identities include effective bases.
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
  // Resolved identities for comparison; definitions alone can retain relative URLs.
  scheme_identities : Array[Scheme]
} derive(Debug)

///|
pub extend Operation with Debug::{to_repr}

///|
pub(all) struct Document {
  source : String
  document_url : String?
  operations : Array[Operation]
  schemes : Array[Scheme]
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
pub extend Document with Debug::{to_repr}

///|
/// Two independently parsed snapshots with peer-required scheme identities.
pub(all) struct DocumentPair {
  before : Document
  after : Document
} derive(Debug)

///|
pub extend DocumentPair with Debug::{to_repr}

///|
pub(all) suberror PairError {
  Before(DocumentError)
  After(DocumentError)
} derive(Debug)

///|
pub extend PairError with Debug::{to_repr}

///|
pub fn PairError::to_string(self : PairError) -> String {
  match self {
    Before(error) => "baseline: " + error.to_string()
    After(error) => "candidate: " + error.to_string()
  }
}

///|
pub impl Show for PairError with fn output(self, logger) {
  logger.write_string(self.to_string())
}

///|
pub extend PairError with Show::{output}

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
  Number(Json)
  Str(String)
  Seq(Array[Value])
  Obj(Map[String, Value])
}

///|
priv suberror AuthError {
  AuthError(String, String, Location)
}

///|
priv struct Limits {
  mut nodes : Int32
  maximum : Int32
}

///|
priv struct ParsedScheme {
  public_scheme : Scheme
  kind : String
  scopes : Map[String, Bool]
  template : Value
  relative : Bool
  contents : Array[String]
}

///|
priv struct Context {
  source : String
  minor : Int32
  declared : Map[String, Value]
  cache : Map[String, ParsedScheme]
  scheme_failures : Map[(String, Bool), AuthError]
  graph : Graph
  entry_servers : ServerSelection
  operation_servers : Map[(String, String), ServerSelection]
  identity_origins : Map[(String, String, String), Array[String]]
  identity_contents : Map[(String, String, String), Array[String]]
  operation_contents : Map[(String, String), Array[String]]
  servers_cache : Map[(String, String), Result[ServerSet, AuthError]]
  identities_cache : Map[
    (String, String, String),
    Result[InstantiatedScheme, AuthError],
  ]
  mut used_identities : Int32
  mut unused_identities : Int32
  mut unused_attempts : Int32
  mut used_identity_bytes : Int32
  mut unused_identity_bytes : Int32
}

///|
priv struct InstantiatedScheme {
  scheme : Scheme
  tuples : Int32
  bytes : Int32
  origins : Array[String]
  contents : Array[String]
}

///|
priv struct ServerSelection {
  value : Value?
  location : Location
}

///|
priv struct ServerVariant {
  base : String
  domain_fingerprint : String
  domain_bytes : Int32
  is_default : Bool
}

///|
priv struct ServerSet {
  variants : Array[ServerVariant]
  origins : Array[String]
}

///|
priv enum ServerPart {
  Literal(String)
  Variable(String)
}

///|
priv struct ParsedSecurity {
  policy : @logic.Policy
  schemes : Array[String]
  atoms : Int32
}

///|
priv struct LoadFailure {
  code : String
  message : String
}

///|
priv struct CachedDocument {
  input : SourceDocument
  value : Result[Value, LoadFailure]
  document_url : String?
}

///|
priv struct Graph {
  documents : Map[String, CachedDocument]
  requests : Map[String, Map[String, Result[String, LoadFailure]]]
  load : ((String, String) -> SourceDocument raise DocumentError)?
  resource_diagnostics : Array[Diagnostic]
  explicit_urls : Bool
  conflicted_origins : Map[String, Bool]
  conflicted_contents : Map[String, Bool]
  origin_children : Map[String, Map[String, Bool]]
  mut bytes : Int32
  mut nodes : Int32
  mut operations : Int32
  mut atoms : Int32
}

///|
priv struct LiveDocument {
  context : Context
  operations : Array[Operation]
  diagnostics : Array[Diagnostic]
  document_url : String?
}

///|
fn pointer_key(pointer : String, key : String) -> String {
  pointer +
  "/" +
  key.replace_all(old="~", new="~0").replace_all(old="/", new="~1")
}

///|
fn Location::key(self : Location, key : String) -> Location {
  { uri: self.uri, pointer: pointer_key(self.pointer, key), }
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
  location : Location,
) -> Unit raise AuthError {
  raise AuthError(code, message, location)
}

///|
fn object(
  value : Value,
  location : Location,
) -> Map[String, Value] raise AuthError {
  match value {
    Obj(obj) => obj
    _ => {
      issue("auth.type", "Expected an object", location)
      abort("unreachable")
    }
  }
}

///|
fn string(value : Value, location : Location) -> String raise AuthError {
  match value {
    Str(text) => text
    _ => {
      issue("auth.type", "Expected a string", location)
      abort("unreachable")
    }
  }
}

///|
fn required_string(
  obj : Map[String, Value],
  key : String,
  at : Location,
) -> String raise AuthError {
  let location = at.key(key)
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
