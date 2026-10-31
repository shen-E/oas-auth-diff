///|
fn write_validation(
  report : @validation.Report,
  format : String,
  source_root~ : @diff.SarifSourceRoot? = None,
) -> Int32 {
  println(
    match format {
      "json" => @validation.render_json(report)
      "sarif" => @diff.render_validation_sarif(report, source_root~)
      _ => @validation.render_text(report)
    },
  )
  for diagnostic in report.diagnostics {
    stderr(
      diagnostic.location.uri +
      "#" +
      diagnostic.location.pointer +
      ": " +
      diagnostic.code +
      ": " +
      diagnostic.message,
    )
  }
  report.exit_code()
}

///|
fn validation_failure(
  message : String,
  source : String,
  format : String,
) -> Int32 {
  write_validation(
    {
      source,
      openapi_version: "",
      metaschema: "",
      violations: [],
      diagnostics: [
        {
          code: "input-error",
          message,
          location: { uri: source, pointer: "", },
        },
      ],
      complete: false,
    },
    format,
  )
}

///|
fn run_validation(args : Array[String]) -> Int32 {
  let format = selected_format(args)
  let (path, format, source_root, local_refs, ref_root, dialect_paths) = try {
    if args.length() < 3 || args[2].has_prefix("--") {
      raise CliError("validate requires one input file")
    }
    let mut format = "text"
    let mut source_root = None
    let mut seen_format = false
    let mut local_refs = false
    let mut ref_root = None
    let dialect_paths : Map[String, String] = Map([])
    let mut index = 3
    while index < args.length() {
      match args[index] {
        "--format" if !seen_format && index + 1 < args.length() => {
          format = args[index + 1]
          if !["text", "json", "sarif"].contains(format) {
            raise CliError("expected --format text, json, or sarif")
          }
          seen_format = true
          index += 2
        }
        "--source-root" if source_root is None && index + 1 < args.length() => {
          if args[index + 1].is_empty() || args[index + 1].has_prefix("--") {
            raise CliError("--source-root requires a directory")
          }
          source_root = Some(args[index + 1])
          index += 2
        }
        "--local-refs" if !local_refs => {
          local_refs = true
          index += 1
        }
        "--ref-root" if ref_root is None && index + 1 < args.length() => {
          if args[index + 1].is_empty() || args[index + 1].has_prefix("--") {
            raise CliError("--ref-root requires a directory")
          }
          ref_root = Some(args[index + 1])
          index += 2
        }
        "--dialect" if index + 1 < args.length() => {
          match args[index + 1].split_once("=") {
            Some((uri, file)) if !uri.is_empty() &&
              !file.is_empty() &&
              !dialect_paths.contains(uri.to_owned()) =>
              dialect_paths[uri.to_owned()] = file.to_owned()
            _ => raise CliError("--dialect requires a unique URI=FILE mapping")
          }
          index += 2
        }
        _ =>
          raise CliError(
            "unknown, duplicate or incomplete validation option: " + args[index],
          )
      }
    }
    if source_root is Some(_) && format != "sarif" {
      raise CliError("--source-root requires --format sarif")
    }
    (
      args[2],
      format,
      source_root,
      local_refs || ref_root is Some(_),
      ref_root,
      dialect_paths,
    )
  } catch {
    error =>
      return validation_failure(
        Show::to_string(error),
        "oas-auth-diff:arguments",
        format,
      )
  }
  let source = read_source(path, local_refs) catch {
    error =>
      return validation_failure(error.to_string(), file_uri(path), format)
  }
  let root = sarif_source_root(source_root, local_refs) catch {
    error =>
      return validation_failure(
        error.to_string(),
        "oas-auth-diff:arguments",
        format,
      )
  }
  let load = local_loader(path, local_refs, ref_root) catch {
    error => return validation_failure(error.to_string(), source.source, format)
  }
  let dialects = Map([])
  let keys = dialect_paths.keys().collect()
  keys.sort()
  for uri in keys {
    let input = read_source(dialect_paths[uri], false) catch {
      error =>
        return validation_failure(error.to_string(), source.source, format)
    }
    let resolver = @openapi.ReferenceResolver::new(input) catch {
      error =>
        return validation_failure(error.to_string(), input.source, format)
    }
    dialects[uri] = resolver.root()
  }
  let report = @validation.validate(
    source.text,
    format=source.format,
    source=source.source,
    load~,
    dialects~,
  ) catch {
    error => return validation_failure(error.to_string(), source.source, format)
  }
  write_validation(report, format, source_root=root)
}
