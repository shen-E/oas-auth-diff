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
}

///|
fn usage() -> String {
  "oas-auth-diff 0.3.0\nUsage: oas-auth-diff compare BEFORE AFTER [--format text|json|sarif] [--local-refs] [--ref-root DIR]\n       oas-auth-diff --help | --version\n\nCompare OpenAPI 3.0/3.1 JSON or YAML files.\n--local-refs loads referenced files within each entry's directory.\n--ref-root DIR enables local references within an explicit boundary.\nExit codes: 0 complete/no regression; 1 verified regression; 2 error/incomplete."
}

///|
fn parse_options(args : Array[String]) -> Options raise CliError {
  match args {
    [_, "compare", before, after, .. rest] => {
      let mut format = "text"
      let mut local_refs = false
      let mut ref_root = None
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
          _ =>
            raise CliError(
              "unknown, duplicate, or incomplete option: " + rest[index],
            )
        }
      }
      if before.has_prefix("--") || after.has_prefix("--") {
        raise CliError("compare requires two input file paths")
      }
      { before, after, format, local_refs, ref_root, }
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
fn load_document(
  path : String,
  local_refs : Bool,
  ref_root : String?,
) -> @openapi.Document raise {
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
  let text = @utf8.decode(bytes[0:length])
  if local_refs {
    let boundary = canonical_root(
      ref_root.unwrap_or(@path.Path(path).resolve().dirname().to_string()),
    )
    @openapi.parse_with_loader(
      text,
      format~,
      source=canonical_source_uri(path),
      load=(from, relative) => load_local_reference(boundary, from, relative),
    )
  } else {
    @openapi.parse_document(text, format~, source=file_uri(path))
  }
}

///|
fn write_report(comparison : @diff.Comparison, format : String) -> Unit {
  println(
    match format {
      "json" => @diff.render_json(comparison)
      "sarif" => @diff.render_sarif(comparison)
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
      println("oas-auth-diff 0.3.0")
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
  let before = load_document(
    options.before,
    options.local_refs,
    options.ref_root,
  ) catch {
    error =>
      return failed(error.to_string(), file_uri(options.before), options.format)
  }
  let after = load_document(options.after, options.local_refs, options.ref_root) catch {
    error =>
      return failed(error.to_string(), file_uri(options.after), options.format)
  }
  let comparison = @diff.compare(before, after)
  write_report(comparison, options.format)
  comparison.exit_code()
}

///|
fn main {
  let status = run(@env.args())
  if status != 0 {
    process_exit(status)
  }
}
