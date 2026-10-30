# Validate an OpenAPI entry document

```sh
oas-auth-diff validate cases/payload.before.yaml
oas-auth-diff validate api.yaml --format json
oas-auth-diff validate api.yaml --format sarif --source-root . > openapi.sarif
```

`validate` loads strict JSON or YAML and checks the entry document against the
bundled official OpenAPI metaschema. It also checks unique operation IDs,
declared security scheme names, duplicate parameters within declaration lists and
missing path-template parameters on literal `paths` operations. It reports
violations independently of the assertions the compatibility solver can prove.
For example, a valid `minimum` or `pattern` declaration can pass validation even
when `breaking` cannot classify its change.

| Exit | Meaning |
| --- | --- |
| 0 | Entry-document metaschema and implemented paths cross checks passed |
| 1 | The parsed entry document has validation violations |
| 2 | Input/usage error, unbundled dialect or incomplete reporting |

Text, JSON and SARIF have the same results. Reports go to stdout; execution
diagnostics go to stderr. JSON has `report_kind: "validation"`, `valid`,
`complete`, the chosen metaschema, violations and diagnostics. `valid` is null
when validation is incomplete. A violation carries the real source URI and
RFC 6901 pointer; no line is fabricated. SARIF treats document violations as
results from a completed execution, and execution failures as notifications.
At most 1000 violations are retained; exceeding that limit returns exit 2.

## Bundled versions and scope

| OpenAPI input | Official resource |
| --- | --- |
| 3.0.x | [3.0 schema, 2024-10-18](https://spec.openapis.org/oas/3.0/schema/2024-10-18) |
| 3.1.x, bundled default dialect | [3.1 schema-base, 2025-09-15](https://spec.openapis.org/oas/3.1/schema-base/2025-09-15) |

The 3.1 base schema includes Schema Object validation through the
[2024-11-10 OpenAPI dialect](https://spec.openapis.org/oas/3.1/dialect/2024-11-10)
and JSON Schema 2020-12 vocabularies. All 13 resources are embedded in
`validation/resources.mbt`; [resources.json](../validation/resources.json) records
their source URLs and SHA-256 digests. Runtime validation performs no network or
file access beyond the CLI's selected entry file. To regenerate the resources,
run `python validation/bundle.py`, then `moon fmt`. The importer refuses changed
checksums.

The validation engine is the Apache-2.0 MoonBit library
[`moonbitstack/moonschema@0.2.0`](https://mooncakes.io/docs/moonbitstack/moonschema%400.2.0).
The entry-document loader, OpenAPI cross checks, reports and compatibility
algorithms remain project code. A small adapter escapes literal hyphens at
character-class boundaries in bundled patterns: this preserves ECMA-262 meaning
while accommodating the core regex parser. The original resource data and
digests are retained, and adapter tests cover allowed and refused component names.

`validate` does not dereference the input document's `$ref` values or assert
`format` annotations. Its JSON report makes both facts explicit. It does not
validate remote resources, custom dialects, callback/webhook cross relationships,
application behavior or every prose-only requirement of OpenAPI. A custom global
or Schema-level dialect returns incomplete rather than an invalid-document
verdict. Examples/default/enum values are ordinary data, so a `$schema` key inside
them does not select a dialect. Use `breaking --local-refs` for supported local
contract references and `compare` for authorization analysis.

## Reuse and verification

Import `shen-E/oas-auth-diff/validation` and call
`validate(text, format=Json|Yaml, source=uri)`. It returns a pure `Report` with
`exit_code()`. `render_text/json` render it, and the `diff` package exposes
`render_validation_sarif`. Fatal strict-input errors raise `openapi.DocumentError`.

`validation/reference.py` checks 32 manually specified valid/invalid documents in
both JSON and YAML against oasdiff v1.35.0. Its exit 102 denotes an upstream load
failure and is recorded separately; the matrix compares valid/invalid verdicts,
without equating the tools' exit codes or report schemas. MoonBit tests additionally
exercise custom dialects, Schema constraints outside the inclusion fragment,
paths cross checks and SARIF behavior.

The OpenAPI resources are distributed under
[Apache-2.0](https://github.com/OAI/OpenAPI-Specification/blob/main/LICENSE).
The JSON Schema resources retain their BSD license in
[JSON_SCHEMA_LICENSE](../validation/JSON_SCHEMA_LICENSE). The pinned dependency
retains its upstream license and copyright notices.
