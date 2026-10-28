///|
/// A validated local directory URI used to display portable SARIF locations.
pub struct SarifSourceRoot {
  priv uri : String
}

///|
pub(all) suberror SarifError {
  InvalidSourceRoot(String)
} derive(Debug)

///|
pub extend SarifError with Debug::{to_repr}

///|
pub fn SarifError::to_string(self : SarifError) -> String {
  let InvalidSourceRoot(message) = self
  message
}

///|
pub impl Show for SarifError with fn output(self, logger) {
  logger.write_string(self.to_string())
}

///|
pub extend SarifError with Show::{output}

///|
/// Validate an absolute local file directory URI and retain one trailing slash.
/// This configures report locations; it does not access the filesystem.
pub fn SarifSourceRoot::new(uri : String) -> SarifSourceRoot raise SarifError {
  let normalized = match sarif_file_identity(uri) {
    Some(uri) => uri
    None =>
      raise InvalidSourceRoot(
        "SARIF source root must be an absolute local file:/// directory URI without authority, query, fragment, unsafe escapes or dot segments",
      )
  }
  {
    uri: if normalized.has_suffix("/") {
      normalized
    } else {
      normalized + "/"
    },
  }
}

///|
/// Return the canonical directory URI used by SARIF's source-root mapping.
pub fn SarifSourceRoot::uri(self : SarifSourceRoot) -> String {
  self.uri
}

///|
fn sarif_path_hex(char : Char) -> Int32? {
  match char {
    '0'..<='9' => Some(char.to_int() - '0'.to_int())
    'a'..<='f' => Some(char.to_int() - 'a'.to_int() + 10)
    'A'..<='F' => Some(char.to_int() - 'A'.to_int() + 10)
    _ => None
  }
}

///|
fn sarif_path_character(char : Char) -> Bool {
  match char {
    'a'..<='z' | 'A'..<='Z' | '0'..<='9' => true
    '-'
    | '.'
    | '_'
    | '~'
    | '!'
    | '$'
    | '&'
    | '\''
    | '('
    | ')'
    | '*'
    | '+'
    | ','
    | ';'
    | '='
    | ':'
    | '@'
    | '/' => true
    _ => false
  }
}

///|
// Preserve escaped filenames instead of decoding and re-encoding their bytes.
// Only inspect escapes that could change path boundaries or dot segments.
fn sarif_file_identity(source : String) -> String? {
  let path = match source.split_once("://") {
    Some((scheme, path)) if scheme.to_owned().to_lower() == "file" =>
      path.to_owned()
    _ => return None
  }
  if !path.has_prefix("/") || path.has_prefix("//") {
    return None
  }
  let chars = path.to_array()
  let out = StringBuilder()
  let digits = "0123456789ABCDEF".to_array()
  let mut index = 0
  while index < chars.length() {
    let char = chars[index]
    if char == '%' {
      if index + 2 >= chars.length() {
        return None
      }
      let byte = match
        (sarif_path_hex(chars[index + 1]), sarif_path_hex(chars[index + 2])) {
        (Some(high), Some(low)) => high * 16 + low
        _ => return None
      }
      if byte < 32 || byte == 127 || byte == 47 || byte == 92 {
        return None
      }
      out.write_char('%')
      out.write_char(digits[byte / 16])
      out.write_char(digits[byte % 16])
      index += 3
    } else if sarif_path_character(char) {
      out.write_char(char)
      index += 1
    } else {
      return None
    }
  }
  let segments = out.to_string().split("/").map(StringView::to_owned).collect()
  for index in 1..<segments.length() {
    let segment = segments[index]
    if segment.is_empty() && index != segments.length() - 1 {
      return None
    }
    let dots = segment.replace_all(old="%2E", new=".")
    if dots == "." || dots == ".." {
      return None
    }
  }
  if segments.length() > 1 {
    let drive = segments[1].to_array()
    if drive.length() == 2 &&
      drive[1] == ':' &&
      (match drive[0] {
        'a'..<='z' | 'A'..<='Z' => true
        _ => false
      }) {
      segments[1] = segments[1].to_upper()
    }
  }
  Some("file://" + segments.join("/"))
}

///|
fn sarif_relative_uri(source : String, root : SarifSourceRoot) -> String? {
  let normalized = match sarif_file_identity(source) {
    Some(uri) => uri
    None => return None
  }
  if !normalized.has_prefix(root.uri) {
    return None
  }
  let relative = normalized[root.uri.length():].to_owned()
  let first = relative.split("/").next().unwrap_or("")
  Some(if first.contains(":") { "./" + relative } else { relative })
}
