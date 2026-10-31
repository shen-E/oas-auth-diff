# Validate OpenAPI documents and references

```sh
oas-auth-diff validate cases/payload.before.yaml
oas-auth-diff validate api.yaml --format json
oas-auth-diff validate api.yaml --local-refs --format sarif --source-root . > openapi.sarif
oas-auth-diff validate api.yaml --ref-root specifications
oas-auth-diff validate cases/dialect.yaml --dialect https://example.test/sensitivity=cases/sensitivity.json
```

`validate` loads strict JSON or YAML and checks OpenAPI objects against the
bundled official metaschemas. It also checks unique operation IDs, declared
security scheme names, duplicate parameters within declaration lists and missing
path-template parameters on literal `paths` operations. It reports syntax
violations independently of the assertions the compatibility solver can prove.
For example, a valid `pattern` declaration can pass validation while `breaking`
cannot classify its change.
The OpenAPI 3.0 check also rejects simultaneous `readOnly: true` and
`writeOnly: true`. Those keywords are annotations in 3.1; the compatibility
command's directional-requiredness profile is described in
[compatibility](compatibility.md#directional-requiredness-and-formats).

| Exit | Meaning |
| --- | --- |
| 0 | Metaschemas, reference targets and implemented paths cross checks passed |
| 1 | Parsed documents or targets have validation violations |
| 2 | Input/usage/reference error, unsupported dialect or incomplete validation |

Reports go to stdout and execution diagnostics to stderr. JSON has
`report_kind: "validation"`, `valid`, `complete`, the entry metaschema,
violations and diagnostics. `valid` is null when validation is incomplete.
`reference_targets_checked` is true only for a complete traversal of supported
reference positions. `format_assertions` is false. Violations retain the actual
source URI and RFC 6901 pointer, including external targets; no line is inferred.
SARIF uses those target locations and includes their file identities in result
fingerprints. At most 1000 violations are retained; overflow returns exit 2.

## References

The walker checks Schema, Path Item, Parameter, Header, Response, Request Body,
Security Scheme, Example, Link and Callback targets at their specified positions,
including components, webhook/callback definitions and nested Schema applicators.
It follows same-document pointers by default. A target is validated as the object
kind required by its use site. A missing target or disabled external file makes
validation incomplete; a resolved target with the wrong structure is invalid.

Recursive Schema graphs are allowed: revisiting a previously checked Schema
terminates traversal. A Reference Object chain that loops without a concrete
target is invalid. Examples, enum/const/default values and extension payloads
remain data; their `$ref` keys do not load files.

`--local-refs` enables referenced JSON/YAML files inside the entry directory;
`--ref-root DIR` sets an explicit boundary. Nested paths resolve against the
referring file, with the same decoding, canonical-source cache, symlink/reparse
checks and directory confinement as `compare` and `breaking`. No network
references are loaded. Limits are 16 MiB, 128 nesting levels and 250000 nodes per
source, 64 documents and 1000000 nodes in the source graph. The validation walk
also stops at depth 128 or 250000 distinct context visits.

Input Schema `$id` resource scopes, `$dynamicRef`, `$recursiveRef` and named-anchor
targets remain incomplete. They are not resolved against a guessed file base.
Validation does not check service behavior, every OpenAPI prose requirement or
cross relationships through callback/webhook and referenced parameter graphs.
Use `breaking` for supported client contracts and `compare` for authorization.

## Dialects and bundled resources

| OpenAPI input | Official entry metaschema |
| --- | --- |
| 3.0.x | [3.0 schema, 2024-10-18](https://spec.openapis.org/oas/3.0/schema/2024-10-18) |
| 3.1.x | [3.1 schema, 2025-09-15](https://spec.openapis.org/oas/3.1/schema/2025-09-15) |

3.1 Schema Objects are checked separately against their effective dialect:
Schema-level `$schema`, inherited `jsonSchemaDialect`, or the default
[2024-11-10 OpenAPI dialect](https://spec.openapis.org/oas/3.1/dialect/2024-11-10).
The standard JSON Schema 2020-12 dialect is also bundled. Separating the generic
OpenAPI object metaschema from the Schema dialect permits explicit custom
registration without applying the default dialect's constant URI constraint.

Repeat `--dialect URI=FILE` to register offline JSON/YAML metaschemas. Each must
have `$id` equal to its registered URI, `$schema` equal to the standard 2020-12
URI, and valid 2020-12 syntax. Required vocabularies must be implemented 2020-12
vocabularies or the OAS base vocabulary. Unknown optional vocabularies may
annotate. Unregistered dialects and unknown required vocabularies return exit 2.
The supplied dialect profile supports ordinary assertions extending bundled
metaschemas. Its references must target bundled resources; internal/cross-custom
references, nested resource IDs and dynamic references are incomplete. The
registry allows at most 64 supplied resources and 20000 JSON nodes total, with
depth 128. This bounds custom metaschema processing before engine initialization.
Supplying a dialect validates Schema syntax; `breaking` still refuses custom
assertion semantics.

All 13 original resources are embedded in `validation/resources.mbt`;
[resources.json](../validation/resources.json) records source URLs and SHA-256
digests. To regenerate, run `python validation/bundle.py`, then `moon fmt`.
The importer refuses changed checksums. Runtime validation reads only selected
inputs and explicitly enabled local sources.

The engine is the Apache-2.0 MoonBit library
[`moonbitstack/moonschema@0.2.0`](https://mooncakes.io/docs/moonbitstack/moonschema%400.2.0).
A small adapter escapes literal hyphens at character-class boundaries for the
core regex parser. Original resource data and digests are retained. The strict
source graph, typed traversal, dialect registration, OpenAPI cross checks and
reports are project code. Numeric/size assertion syntax also uses the exact
Schema parser for standard dialects and registered dialects directly extending
them: for example, `minLength: 1e-400` remains a noninteger even when a binary
floating-point value underflows to zero.

## Library and verification

Import `shen-E/oas-auth-diff/validation` and call
`validate(text, format=Json|Yaml, source=uri)`. Optional `load=Some(loader)` uses
the same `openapi.SourceDocument` loader contract as other parsers;
`dialects=Map([(uri, metaschema)])` registers resources without I/O. `Report`
provides `exit_code()`, `render_text/json` render it, and `diff` exposes
`render_validation_sarif`. Fatal strict-entry errors raise `openapi.DocumentError`.
`openapi.ReferenceResolver` separately exposes strict source loading, fresh root
snapshots and controlled JSON Pointer resolution for library consumers.

`validation/reference.py` checks 50 manually specified valid/invalid documents
in JSON and YAML against oasdiff v1.35.0. Upstream exit 102 is a loader failure,
recorded separately; the matrix compares verdicts rather than identical exit
codes. MoonBit tests additionally cover local loaders, dialect vocabularies,
source origins, cycles, data/reference separation and SARIF fingerprints.

OpenAPI resources retain [Apache-2.0](https://github.com/OAI/OpenAPI-Specification/blob/main/LICENSE).
JSON Schema resources retain their BSD license in
[JSON_SCHEMA_LICENSE](../validation/JSON_SCHEMA_LICENSE). Dependencies retain
their upstream license and copyright notices.
