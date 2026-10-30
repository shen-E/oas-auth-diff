///|
/// A validated parameter declaration with its resolved source location.
pub struct ParameterContract {
  name : String
  position : String
  required : Bool
  definition : Json
  location : Location
  priv shape : String
}

///|
/// Whether two parameter definitions agree apart from requiredness and labels.
pub fn ParameterContract::same_shape(
  self : ParameterContract,
  other : ParameterContract,
) -> Bool {
  self.shape == other.shape
}

///|
/// Effective path-level and operation-level parameters of one HTTP operation.
pub struct OperationContract {
  http_method : String
  path : String
  parameters : Array[ParameterContract]
  location : Location
  complete : Bool
  priv remainder : String
}

///|
/// Whether fields outside the parameter list are unchanged.
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
/// Whether document fields outside paths and parameter components agree.
pub fn Specification::same_remainder(
  self : Specification,
  other : Specification,
) -> Bool {
  self.remainder == other.remainder
}
