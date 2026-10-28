///|
priv suberror CliError {
  CliError(String)
}

///|
impl Show for CliError with fn output(self, logger) {
  let CliError(message) = self
  logger.write_string(message)
}

///|
priv struct Options {
  before : String
  after : String
  format : String
  local_refs : Bool
  ref_root : String?
  source_root : String?
  before_document_url : String?
  after_document_url : String?
}

///|
fn usage() -> String {
  "oas-auth-diff 0.7.0\nUsage: oas-auth-diff compare BEFORE AFTER [--format text|json|sarif] [--local-refs] [--ref-root DIR]\n       [--before-document-url URL] [--after-document-url URL] [--source-root DIR]\n       oas-auth-diff --help | --version\n\nCompare OpenAPI 3.0/3.1 JSON or YAML files.\n--local-refs loads referenced files within each entry's directory.\n--ref-root DIR enables local references within an explicit boundary.\n--before-document-url URL sets the absolute HTTP(S) address of the before specification document.\n--after-document-url URL sets the absolute HTTP(S) address of the after specification document.\n--source-root DIR makes SARIF artifact paths relative to the source root; requires --format sarif.\nDocument URLs resolve relative server URLs; they do not enable local references or fetch URLs.\nExit codes: 0 complete/no regression; 1 verified regression; 2 error/incomplete."
}

///|
fn parse_options(args : Array[String]) -> Options raise CliError {
  match args {
    [_, "compare", before, after, .. rest] => {
      let mut format = "text"
      let mut local_refs = false
      let mut ref_root = None
      let mut source_root = None
      let mut before_document_url = None
      let mut after_document_url = None
      let mut seen_format = false
      let mut seen_local = false
      let mut index = 0
      while index < rest.length() {
        match rest[index] {
          "--local-refs" if !seen_local => {
            local_refs = true
            seen_local = true
            index += 1
          }
          "--format" if !seen_format && index + 1 < rest.length() => {
            match rest[index + 1] {
              "text" | "json" | "sarif" as value => format = value
              _ => raise CliError("expected --format text, json, or sarif")
            }
            seen_format = true
            index += 2
          }
          "--ref-root" if ref_root is None && index + 1 < rest.length() => {
            let value = rest[index + 1]
            if value.is_empty() || value.has_prefix("--") {
              raise CliError("--ref-root requires a directory")
            }
            ref_root = Some(value)
            local_refs = true
            index += 2
          }
          "--source-root" if source_root is None && index + 1 < rest.length() => {
            let value = rest[index + 1]
            if value.is_empty() || value.has_prefix("--") {
              raise CliError("--source-root requires a directory")
            }
            source_root = Some(value)
            index += 2
          }
          "--before-document-url" if before_document_url is None &&
            index + 1 < rest.length() => {
            let value = rest[index + 1]
            if value.is_empty() || value.has_prefix("--") {
              raise CliError("--before-document-url requires a document URL")
            }
            before_document_url = Some(value)
            index += 2
          }
          "--after-document-url" if after_document_url is None &&
            index + 1 < rest.length() => {
            let value = rest[index + 1]
            if value.is_empty() || value.has_prefix("--") {
              raise CliError("--after-document-url requires a document URL")
            }
            after_document_url = Some(value)
            index += 2
          }
          _ =>
            raise CliError(
              "unknown, duplicate, or incomplete option: " + rest[index],
            )
        }
      }
      if before.has_prefix("--") || after.has_prefix("--") {
        raise CliError("compare requires two input file paths")
      }
      if source_root is Some(_) && format != "sarif" {
        raise CliError("--source-root requires --format sarif")
      }
      {
        before,
        after,
        format,
        local_refs,
        ref_root,
        source_root,
        before_document_url,
        after_document_url,
      }
    }
    _ =>
      raise CliError("expected compare BEFORE AFTER [--format text|json|sarif]")
  }
}

///|
fn selected_format(args : Array[String]) -> String {
  for index in 0..<(args.length() - 1) {
    if args[index] == "--format" &&
      (args[index + 1] == "json" || args[index + 1] == "sarif") {
      return args[index + 1]
    }
  }
  "text"
}

///|
fn file_uri(path : String) -> String {
  let absolute = @path.Path(path)
    .resolve()
    .to_string()
    .split("\\")
    .to_array()
    .join("/")
  let bytes = @utf8.encode(absolute)
  let buffer = StringBuilder()
  let hex = "0123456789ABCDEF".to_array()
  for byte in bytes {
    let number = byte.to_int()
    if (number >= 65 && number <= 90) ||
      (number >= 97 && number <= 122) ||
      (number >= 48 && number <= 57) ||
      number == 45 ||
      number == 46 ||
      number == 95 ||
      number == 126 ||
      number == 47 ||
      number == 58 {
      buffer.write_char(number.to_char().unwrap())
    } else {
      buffer.write_char('%')
      buffer.write_char(hex[number / 16])
      buffer.write_char(hex[number % 16])
    }
  }
  let encoded = buffer.to_string()
  if encoded.has_prefix("//") {
    "file:\{encoded}"
  } else if encoded.has_prefix("/") {
    "file://\{encoded}"
  } else {
    "file:///\{encoded}"
  }
}

///|
fn read_source(
  path : String,
  local_refs : Bool,
) -> @openapi.SourceDocument raise {
  let extension = @path.Path(path).extname().to_owned()
  let format = match extension {
    ".json" => @openapi.Json
    ".yaml" | ".yml" => @openapi.Yaml
    _ =>
      raise CliError(
        "input must have a .json, .yaml, or .yml extension: \{path}",
      )
  }
  let bytes = Bytes::make(16777217, 0)
  let length = read_bounded(@utf8.encode(path), bytes)
  match length {
    -1 => raise CliError("cannot open input file: \{path}")
    -2 => raise CliError("cannot read input file: \{path}")
    -3 => raise CliError("input must be a regular file: \{path}")
    -4 => raise CliError("input exceeds 16 MiB: \{path}")
    _ if length > 16777216 => raise CliError("input exceeds 16 MiB: \{path}")
    _ => ()
  }
  {
    text: @utf8.decode(bytes[0:length]),
    format,
    source: if local_refs {
      canonical_source_uri(path)
    } else {
      file_uri(path)
    },
  }
}

///|
fn local_loader(
  path : String,
  enabled : Bool,
  ref_root : String?,
) -> ((String, String) -> @openapi.SourceDocument raise @openapi.DocumentError)? raise {
  if !enabled {
    return None
  }
  let boundary = canonical_root(
    ref_root.unwrap_or(@path.Path(path).resolve().dirname().to_string()),
  )
  Some((from, relative) => load_local_reference(boundary, from, relative))
}

///|
fn sarif_source_root(
  path : String?,
  local_refs : Bool,
) -> @diff.SarifSourceRoot? raise {
  match path {
    None => None
    Some(path) => {
      let canonical = canonical_root(path)
      let uri = file_uri(if local_refs { canonical } else { path })
      Some(@diff.SarifSourceRoot::new(uri))
    }
  }
}

///|
fn write_report(
  comparison : @diff.Comparison,
  format : String,
  source_root~ : @diff.SarifSourceRoot? = None,
) -> Unit {
  println(
    match format {
      "json" => @diff.render_json(comparison)
      "sarif" => @diff.render_sarif(comparison, source_root~)
      _ => @diff.render_text(comparison)
    },
  )
  for diagnostic in comparison.diagnostics {
    stderr(
      "\{diagnostic.location.uri}#\{diagnostic.location.pointer}: \{diagnostic.code}: \{diagnostic.message}",
    )
  }
}

///|
fn failed(message : String, source : String, format : String) -> Int32 {
  let comparison = @diff.failure_report([
    @openapi.Diagnostic::{
      code: "input-error",
      message,
      location: { uri: source, pointer: "", },
    },
  ])
  write_report(comparison, format)
  2
}

///|
fn run(args : Array[String]) -> Int32 {
  match args {
    [_] | [_, "--help"] | [_, "-h"] => {
      println(usage())
      return 0
    }
    [_, "--version"] => {
      println("oas-auth-diff 0.7.0")
      return 0
    }
    _ => ()
  }
  let options = parse_options(args) catch {
    error =>
      return failed(
        Show::to_string(error),
        "oas-auth-diff:arguments",
        selected_format(args),
      )
  }
  let source_root = sarif_source_root(options.source_root, options.local_refs) catch {
    error =>
      return failed(
        error.to_string(),
        "oas-auth-diff:arguments",
        options.format,
      )
  }
  let before = read_source(options.before, options.local_refs) catch {
    error =>
      return failed(error.to_string(), file_uri(options.before), options.format)
  }
  let before_load = local_loader(
    options.before,
    options.local_refs,
    options.ref_root,
  ) catch {
    error => return failed(error.to_string(), before.source, options.format)
  }
  let after = read_source(options.after, options.local_refs) catch {
    error =>
      return failed(error.to_string(), file_uri(options.after), options.format)
  }
  let after_load = local_loader(
    options.after,
    options.local_refs,
    options.ref_root,
  ) catch {
    error => return failed(error.to_string(), after.source, options.format)
  }
  let pair = @openapi.parse_pair(
    before,
    after,
    before_load~,
    after_load~,
    before_document_url=options.before_document_url,
    after_document_url=options.after_document_url,
  ) catch {
    @openapi.Before(error) =>
      return failed(error.to_string(), before.source, options.format)
    @openapi.After(error) =>
      return failed(error.to_string(), after.source, options.format)
  }
  let comparison = @diff.compare(pair.before, pair.after)
  write_report(comparison, options.format, source_root~)
  comparison.exit_code()
}

///|
fn main {
  let status = run(@env.args())
  if status != 0 {
    process_exit(status)
  }
}
