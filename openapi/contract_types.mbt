///|
/// A validated parameter declaration with its resolved source location.
pub struct ParameterContract {
  name : String
  position : String
  required : Bool
  definition : Json
  location : Location
  schema : SchemaContract?
  priv shape : String
}

///|
/// A resolved Schema value and its actual source origin.
pub struct SchemaContract {
  definition : Json
  location : Location
}

///|
pub struct MediaContract {
  media_type : String
  schema : SchemaContract?
  location : Location
  priv remainder : String
}

///|
pub fn MediaContract::same_remainder(
  self : MediaContract,
  other : MediaContract,
) -> Bool {
  self.remainder == other.remainder
}

///|
pub struct BodyContract {
  required : Bool
  content : Array[MediaContract]
  location : Location
  priv remainder : String
}

///|
pub fn BodyContract::same_remainder(
  self : BodyContract,
  other : BodyContract,
) -> Bool {
  self.remainder == other.remainder
}

///|
pub struct ResponseContract {
  status : String
  content : Array[MediaContract]
  headers : Array[HeaderContract]
  location : Location
  priv remainder : String
}

///|
/// A resolved response header; HTTP names compare without case.
pub struct HeaderContract {
  name : String
  required : Bool
  schema : SchemaContract?
  content : Array[MediaContract]
  location : Location
  priv remainder : String
}

///|
pub fn HeaderContract::same_remainder(
  self : HeaderContract,
  other : HeaderContract,
) -> Bool {
  self.remainder == other.remainder
}

///|
pub fn ResponseContract::same_remainder(
  self : ResponseContract,
  other : ResponseContract,
) -> Bool {
  self.remainder == other.remainder
}

///|
/// Whether non-Schema fields agree apart from requiredness and labels.
pub fn ParameterContract::same_shape(
  self : ParameterContract,
  other : ParameterContract,
) -> Bool {
  self.shape == other.shape
}

///|
/// Effective parameters, request body and responses of one HTTP operation.
pub struct OperationContract {
  http_method : String
  path : String
  parameters : Array[ParameterContract]
  request_body : BodyContract?
  responses : Array[ResponseContract]
  location : Location
  complete : Bool
  priv remainder : String
}

///|
/// Whether fields outside parameters, request bodies and responses agree.
pub fn OperationContract::same_remainder(
  self : OperationContract,
  other : OperationContract,
) -> Bool {
  self.remainder == other.remainder
}

///|
/// A specification snapshot; this does not assert full OpenAPI validation.
pub struct Specification {
  source : String
  version : String
  operations : Array[OperationContract]
  diagnostics : Array[Diagnostic]
  priv root : Value
  priv remainder : String
}

///|
/// Return a fresh snapshot, preserving numeric contents and nested fields.
pub fn Specification::to_json(self : Specification) -> Json {
  value_json(self.root)
}

///|
/// Whether document fields outside paths and extracted components agree.
pub fn Specification::same_remainder(
  self : Specification,
  other : Specification,
) -> Bool {
  self.remainder == other.remainder
}
