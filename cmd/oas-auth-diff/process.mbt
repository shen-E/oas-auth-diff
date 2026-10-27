///|
extern "C" fn process_exit(code : Int32) = "oas_auth_diff_exit"

///|
#borrow(text)
extern "C" fn process_stderr(text : Bytes, length : Int32) = "oas_auth_diff_stderr"

///|
#borrow(path, output)
extern "C" fn read_bounded(path : Bytes, output : Bytes) -> Int32 = "oas_auth_diff_read_bounded"

///|
fn stderr(message : String) -> Unit {
  let bytes = @utf8.encode(message)
  process_stderr(bytes, bytes.length())
}
