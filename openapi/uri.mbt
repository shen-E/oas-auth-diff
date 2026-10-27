///|
priv struct HttpReference {
  scheme : String?
  authority : String?
  path : String
  query : String?
}

///|
fn url_alpha(char : Char) -> Bool {
  match char {
    'a'..<='z' | 'A'..<='Z' => true
    _ => false
  }
}

///|
fn url_digit(char : Char) -> Bool {
  char >= '0' && char <= '9'
}

///|
fn url_unreserved(char : Char) -> Bool {
  url_alpha(char) ||
  url_digit(char) ||
  (match char {
    '-' | '.' | '_' | '~' => true
    _ => false
  })
}

///|
fn url_subdelimiter(char : Char) -> Bool {
  match char {
    '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' => true
    _ => false
  }
}

///|
// Only normalize escape spelling; encoded delimiters never become syntax.
fn url_escapes(text : String, location : Location) -> String raise AuthError {
  let chars = text.to_array()
  let out = StringBuilder()
  let digits = "0123456789ABCDEF".to_array()
  let mut index = 0
  while index < chars.length() {
    let char = chars[index]
    if char == '%' {
      if index + 2 >= chars.length() {
        issue(
          "auth.url", "Truncated percent escape in authentication URL", location,
        )
      }
      match
        (
          hex_digit(chars[index + 1].to_int()),
          hex_digit(chars[index + 2].to_int()),
        ) {
        (Some(high), Some(low)) => {
          out.write_char('%')
          out.write_char(digits[high])
          out.write_char(digits[low])
        }
        _ =>
          issue(
            "auth.url", "Invalid percent escape in authentication URL", location,
          )
      }
      index += 3
    } else {
      if !url_unreserved(char) &&
        !url_subdelimiter(char) &&
        !(match char {
          ':' | '/' | '?' | '#' | '[' | ']' | '@' => true
          _ => false
        }) {
        issue(
          "auth.url", "Authentication URL contains a non-URI character; encode non-ASCII characters",
          location,
        )
      }
      out.write_char(char)
      index += 1
    }
  }
  out.to_string()
}

///|
fn url_component(
  text : String,
  query : Bool,
  location : Location,
) -> Unit raise AuthError {
  if !text
    .iter()
    .all(char => {
      url_unreserved(char) ||
      url_subdelimiter(char) ||
      char == '%' ||
      char == ':' ||
      char == '@' ||
      char == '/' ||
      (query && char == '?')
    }) {
    issue(
      "auth.url", "Invalid character in authentication URL path or query", location,
    )
  }
}

///|
fn parse_http_reference(
  text : String,
  location : Location,
) -> HttpReference raise AuthError {
  let text = url_escapes(text, location)
  if text.contains_char('#') {
    issue(
      "auth.url", "Authentication URLs must not contain fragments", location,
    )
  }
  let (head, query) = match text.split_once("?") {
    Some((head, query)) => (head.to_owned(), Some(query.to_owned()))
    None => (text, None)
  }
  let first_slash = head.find("/").unwrap_or(head.length())
  let (scheme, remainder) = match head.find(":") {
    Some(colon) if colon < first_slash => {
      let name = head[0:colon].to_owned()
      let chars = name.to_array()
      if chars.is_empty() ||
        !url_alpha(chars[0]) ||
        !chars.all(char => {
          url_alpha(char) ||
          url_digit(char) ||
          char == '+' ||
          char == '-' ||
          char == '.'
        }) {
        issue("auth.url", "Invalid authentication URL scheme", location)
      }
      let name = name.to_lower()
      if name != "http" && name != "https" {
        issue(
          "auth.url", "Authentication URLs require the HTTP or HTTPS scheme", location,
        )
      }
      (Some(name), head[colon + 1:].to_owned())
    }
    _ => (None, head)
  }
  let (authority, path) = if remainder.has_prefix("//") {
    let rest = remainder[2:].to_owned()
    match rest.find("/") {
      Some(slash) => (Some(rest[0:slash].to_owned()), rest[slash:].to_owned())
      None => (Some(rest), "")
    }
  } else {
    (None, remainder)
  }
  if scheme is Some(_) && authority is None {
    issue(
      "auth.url", "Absolute HTTP authentication URLs require // and a host", location,
    )
  }
  url_component(path, false, location)
  if query is Some(query) {
    url_component(query, true, location)
  }
  { scheme, authority, path, query, }
}

///|
fn url_ipv4(text : String) -> Array[Int32]? {
  let pieces = text.split(".").to_array()
  if pieces.length() != 4 {
    return None
  }
  let numbers = []
  for piece in pieces {
    let chars = piece.to_owned().to_array()
    if chars.is_empty() ||
      chars.length() > 3 ||
      (chars.length() > 1 && chars[0] == '0') {
      return None
    }
    let mut number = 0
    for char in chars {
      if !url_digit(char) {
        return None
      }
      number = number * 10 + char.to_int() - 48
    }
    if number > 255 {
      return None
    }
    numbers.push(number)
  }
  Some(numbers)
}

///|
fn url_ipv6_side(text : String, ipv4 : Bool) -> Array[Int32]? {
  if text.is_empty() {
    return Some([])
  }
  let parts = text.split(":").to_array()
  let words = []
  for index in 0..<parts.length() {
    let piece = parts[index].to_owned()
    if piece.contains_char('.') {
      if !ipv4 || index != parts.length() - 1 {
        return None
      }
      match url_ipv4(piece) {
        Some(octets) => {
          words.push(octets[0] * 256 + octets[1])
          words.push(octets[2] * 256 + octets[3])
        }
        None => return None
      }
    } else {
      if piece.is_empty() || piece.length() > 4 {
        return None
      }
      let mut number = 0
      for char in piece {
        match hex_digit(char.to_int()) {
          Some(digit) => number = number * 16 + digit
          None => return None
        }
      }
      words.push(number)
    }
  }
  Some(words)
}

///|
fn url_hex_word(number : Int32) -> String {
  let digits = "0123456789abcdef".to_array()
  let out = StringBuilder()
  let mut started = false
  for shift in [12, 8, 4, 0] {
    let digit = (number >> shift) & 15
    if digit != 0 || started || shift == 0 {
      started = true
      out.write_char(digits[digit])
    }
  }
  out.to_string()
}

///|
fn url_ipv6(text : String) -> String? {
  if text.length() > 45 {
    return None
  }
  let halves = text.split("::").to_array()
  let words = match halves {
    [whole] => {
      let words = url_ipv6_side(whole.to_owned(), true).unwrap_or([])
      if words.length() != 8 {
        return None
      }
      words
    }
    [left, right] => {
      let left = match url_ipv6_side(left.to_owned(), false) {
        Some(value) => value
        None => return None
      }
      let right = match url_ipv6_side(right.to_owned(), true) {
        Some(value) => value
        None => return None
      }
      if left.length() + right.length() >= 8 {
        return None
      }
      let words = left.copy()
      for _ in 0..<(8 - left.length() - right.length()) {
        words.push(0)
      }
      for word in right {
        words.push(word)
      }
      words
    }
    _ => return None
  }
  let mut best_start = 0
  let mut best_length = 0
  let mut index = 0
  while index < 8 {
    if words[index] == 0 {
      let start = index
      while index < 8 && words[index] == 0 {
        index += 1
      }
      if index - start > best_length {
        best_start = start
        best_length = index - start
      }
    } else {
      index += 1
    }
  }
  if best_length < 2 {
    return Some(words.map(url_hex_word).join(":"))
  }
  let left = []
  let right = []
  for i in 0..<best_start {
    left.push(url_hex_word(words[i]))
  }
  for i in (best_start + best_length)..<8 {
    right.push(url_hex_word(words[i]))
  }
  Some(left.join(":") + "::" + right.join(":"))
}

///|
fn url_dns_host(text : String, location : Location) -> String raise AuthError {
  if text.length() > 762 {
    issue(
      "auth.url", "Authentication URL host exceeds DNS name limits", location,
    )
  }
  let chars = text.to_array()
  let decoded = StringBuilder()
  let mut index = 0
  while index < chars.length() {
    if chars[index] == '%' {
      // Escape syntax has already been checked by parse_http_reference.
      let high = hex_digit(chars[index + 1].to_int()).unwrap()
      let low = hex_digit(chars[index + 2].to_int()).unwrap()
      decoded.write_char((high * 16 + low).to_char().unwrap())
      index += 3
    } else {
      decoded.write_char(chars[index])
      index += 1
    }
  }
  let host = decoded.to_string()
  let name = if host.has_suffix(".") {
    host[0:host.length() - 1].to_owned()
  } else {
    host
  }
  if name.is_empty() || name.length() > 253 {
    issue("auth.url", "Invalid authentication URL host", location)
  }
  if name.iter().all(char => url_digit(char) || char == '.') {
    if url_ipv4(name) is None {
      issue(
        "auth.url", "Invalid or ambiguous IPv4 authentication URL host", location,
      )
    }
  }
  for label in name.split(".") {
    let chars = label.to_owned().to_array()
    if chars.is_empty() ||
      chars.length() > 63 ||
      !(url_alpha(chars[0]) || url_digit(chars[0])) ||
      !(url_alpha(chars[chars.length() - 1]) ||
      url_digit(chars[chars.length() - 1])) ||
      !chars.all(char => url_alpha(char) || url_digit(char) || char == '-') {
      issue(
        "auth.url", "Authentication URL host requires ASCII DNS labels, IPv4, or bracketed IPv6",
        location,
      )
    }
  }
  url_escapes(text.to_lower(), location)
}

///|
fn url_port(
  text : String?,
  scheme : String,
  location : Location,
) -> String raise AuthError {
  match text {
    None | Some("") => ""
    Some(text) => {
      let mut number = 0
      for char in text {
        if !url_digit(char) {
          issue(
            "auth.url", "Authentication URL port must contain decimal digits", location,
          )
        }
        number = number * 10 + char.to_int() - 48
        if number > 65535 {
          issue("auth.url", "Authentication URL port exceeds 65535", location)
        }
      }
      if (scheme == "http" && number == 80) ||
        (scheme == "https" && number == 443) {
        ""
      } else {
        ":" + number.to_string()
      }
    }
  }
}

///|
fn url_authority(
  text : String,
  scheme : String,
  location : Location,
) -> String raise AuthError {
  if text.is_empty() || text.contains_char('@') {
    issue(
      "auth.url", "Authentication URL requires a host without user information",
      location,
    )
  }
  let (host, port) = if text.has_prefix("[") {
    let close = match text.find("]") {
      Some(close) => close
      None => {
        issue("auth.url", "Unclosed IPv6 authentication URL host", location)
        abort("unreachable")
      }
    }
    let literal = text[1:close].to_owned()
    let host = match url_ipv6(literal) {
      Some(host) => "[" + host + "]"
      None => {
        issue(
          "auth.url", "Invalid IPv6 authentication URL host; zone identifiers and IPvFuture are unsupported",
          location,
        )
        abort("unreachable")
      }
    }
    let suffix = text[close + 1:].to_owned()
    let port = if suffix.is_empty() {
      None
    } else if suffix.has_prefix(":") {
      Some(suffix[1:].to_owned())
    } else {
      issue(
        "auth.url", "Unexpected data after IPv6 authentication URL host", location,
      )
      abort("unreachable")
    }
    (host, port)
  } else {
    if text.contains_char('[') || text.contains_char(']') {
      issue("auth.url", "Invalid brackets in authentication URL host", location)
    }
    match text.split(":").to_array() {
      [host] => (url_dns_host(host.to_owned(), location), None)
      [host, port] =>
        (url_dns_host(host.to_owned(), location), Some(port.to_owned()))
      _ => {
        issue(
          "auth.url", "IPv6 authentication URL hosts must use brackets", location,
        )
        abort("unreachable")
      }
    }
  }
  host + url_port(port, scheme, location)
}

///|
// RFC 3986 section 5.2.4, applied to an authority's absolute path. Empty
// segments remain significant; only literal dot segments are interpreted.
fn url_remove_dots(path : String) -> String {
  let pieces = path.split("/").to_array()
  let out : Array[String] = []
  for index in 0..<pieces.length() {
    let piece = pieces[index].to_owned()
    if piece == "." {
      if index == pieces.length() - 1 {
        out.push("")
      }
    } else if piece == ".." {
      if out.length() > 1 {
        ignore(out.pop())
      }
      if index == pieces.length() - 1 {
        out.push("")
      }
    } else {
      out.push(piece)
    }
  }
  out.join("/")
}

///|
fn url_merge(base : String, reference : String) -> String {
  match base.rev_find("/") {
    Some(slash) => base[0:slash + 1].to_owned() + reference
    None => "/" + reference
  }
}

///|
// Resolution follows RFC 3986 sections 5.2-5.4. HTTP normalization is applied
// after merging, without decoding percent-encoded path or query delimiters.
fn resolve_http_url(
  reference : String,
  base : String?,
  location : Location,
) -> String raise AuthError {
  let reference = parse_http_reference(reference, location)
  let (scheme, authority, path, query) = if reference.scheme is Some(scheme) {
    (scheme, reference.authority.unwrap(), reference.path, reference.query)
  } else {
    let base = match base {
      Some(base) => parse_http_reference(base, location)
      None => {
        issue(
          "auth.url", "Relative authentication URL requires an absolute HTTP(S) base",
          location,
        )
        abort("unreachable")
      }
    }
    let (scheme, authority) = match (base.scheme, base.authority) {
      (Some(scheme), Some(authority)) => (scheme, authority)
      _ => {
        issue(
          "auth.url", "Authentication URL base must be an absolute HTTP(S) URL",
          location,
        )
        abort("unreachable")
      }
    }
    // Validate the entire supplied base even when the reference replaces its host.
    ignore(url_authority(authority, scheme, location))
    if reference.authority is Some(authority) {
      (scheme, authority, reference.path, reference.query)
    } else if reference.path.is_empty() {
      let query = match reference.query {
        Some(query) => Some(query)
        None => base.query
      }
      (scheme, authority, base.path, query)
    } else {
      let path = if reference.path.has_prefix("/") {
        reference.path
      } else {
        url_merge(base.path, reference.path)
      }
      (scheme, authority, path, reference.query)
    }
  }
  let authority = url_authority(authority, scheme, location)
  let path = url_remove_dots(path)
  let path = if path.is_empty() { "/" } else { path }
  let query = match query {
    Some(query) => "?" + query
    None => ""
  }
  scheme + "://" + authority + path + query
}
