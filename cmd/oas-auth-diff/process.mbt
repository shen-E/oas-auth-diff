///|
extern "C" fn process_exit(code : Int32) = "oas_auth_diff_exit"

///|
#borrow(text)
extern "C" fn process_stderr(text : Bytes, length : Int32) = "oas_auth_diff_stderr"

///|
#borrow(path, output)
extern "C" fn read_bounded(path : Bytes, output : Bytes) -> Int32 = "oas_auth_diff_read_bounded"

///|
#borrow(path, output)
extern "C" fn canonical_path(
  path : Bytes,
  output : Bytes,
  directory : Int32,
) -> Int32 = "oas_auth_diff_canonical"

///|
#borrow(root, relative, output, canonical)
extern "C" fn read_confined(
  root : Bytes,
  relative : Bytes,
  output : Bytes,
  canonical : Bytes,
) -> Int32 = "oas_auth_diff_read_confined"

///|
fn stderr(message : String) -> Unit {
  let bytes = @utf8.encode(message)
  process_stderr(bytes, bytes.length())
}
