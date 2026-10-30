# OpenAPI changes and client compatibility

Use `diff` to inspect general document edits, `breaking` to gate client contract
changes, and `compare` to check authorization regressions. The commands have
separate report kinds and analysis scopes.

```sh
oas-auth-diff diff cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff summary cases/payload.before.yaml cases/payload.after.json
oas-auth-diff breaking cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff breaking cases/payload.before.yaml cases/payload.after.json --format sarif --source-root .
oas-auth-diff checks --format json
```

The example rejects the formerly valid request `{"state":"draft"}` and permits
a response without the formerly guaranteed `id`. Both Schema findings have
independently evaluated data witnesses. `witness_verified: true` distinguishes
a verified JSON `null` witness from a finding without a witness. These describe
Schema instances rather than complete HTTP exchanges.

## General document diff

`diff` enumerates added, removed and modified source values, including
documentation, extensions, security declarations and unsupported Schema fields.
Changes contain RFC 6901 pointers and before/after values in stable pointer order.
Object field order and equivalent decimal spellings do not create edits; array
order remains significant. `summary` counts those edits.

Both commands load strict JSON/YAML snapshots of the entry documents. They do
not expand references, normalize set-valued arrays or infer compatibility.
A referenced file changing at an unchanged `$ref` site is observed by `breaking`
when that contract is resolved. Structural `complete` describes value enumeration,
not specification validation. Text and JSON are supported. Successful diffs exit 0,
including when values changed; input errors exit 2. Reference-loading, deployment
URL and SARIF options belong to the semantic commands.

## Compatibility checks

`breaking` supports text, JSON and SARIF. It exits 0 for complete analysis without
findings, 1 for confirmed breaks, and 2 for input errors or incomplete analysis.
Confirmed findings survive incomplete results. JSON identifies
`report_kind: "compatibility"`, `scope: "endpoint-parameter-and-payload-schema"`
and the exact `checked_rules`.

| Check | Trigger |
| --- | --- |
| `endpoint-removed` | An existing method/path-template identity disappears |
| `request-parameter-added-required` | A required query/header/cookie parameter is added |
| `request-parameter-became-required` | An optional parameter becomes required |
| `request-schema-narrowed` | An old parameter/body instance is rejected by the new Schema |
| `response-schema-widened` | A new response instance is rejected by the old Schema |
| `request-body-added-required` | An operation gains a required request body |
| `request-body-became-required` | An optional body becomes required |
| `request-body-media-type-removed` | An accepted request media type loses coverage |
| `response-media-type-added` | A response gains a media type absent from the old contract |

Request comparison proves **old instances are included in new instances**;
response comparison proves **new instances are included in old instances**.
The pure `schema` package supports types (including integer/number inclusion),
enums with exact decimal equality, nested object properties and requiredness,
`additionalProperties`, and array `items`. OpenAPI 3.0 `nullable` applies only
with an explicit type; 3.1 type unions and boolean schemas are supported.
Enum, required-name and type-array order do not change compatibility.

The inclusion algorithm returns a proof, a counterexample or Unknown. Each
counterexample is checked with a separate instance evaluator. Failure to prove
inclusion alone never becomes a finding. Schema parsing/comparison have
20000-step budgets; Schema and instance nesting is limited to 128. Exhaustion
produces an incomplete result.

Unsupported Schema assertions produce diagnostics even when present on both
sides. These include numeric/string/array-size bounds, patterns, formats,
defaults, readOnly/writeOnly behavior, composition (`allOf`/`anyOf`/`oneOf`),
discriminators, dynamic references and custom dialects. This is a bounded
checker, not a complete JSON Schema inclusion solver.

Path-level parameters are inherited; operation declarations override them by
`(in, name)`. Header names compare without case and reserved header parameters
are ignored as required by OpenAPI. Path declarations must match their template
and be required. Template parameter renames preserve matching by position.

Parameter, body, response, Path Item and nested Schema references use the bounded,
caller-controlled local source graph. `--local-refs`/`--ref-root` retain their
directory confinement. Components can be renamed or inlined without changing a
resolved Schema. Recursive Schemas, assertion siblings beside a Schema `$ref`,
`$id` resource scopes, unavailable targets and unresolved header/link references
produce diagnostics. References inside example data are not loaded. Locations
identify the actual referenced Schema resource without invented line numbers.

Media type names compare without case. Wildcards and media type parameters require
range matching and are incomplete. Response status additions/removals, response
headers/links, parameter serialization changes/removals, removed request bodies,
and other changed document/operation fields remain unclassified. Response
descriptions and Schema documentation edits do not create breaks. Authentication
changes belong to `compare`; run both semantic gates in CI.

## Library

Parse with `openapi.parse_specification`, optionally supplying a loader, then call
`compat.compare`. The model retains effective parameters, bodies, responses and
resolved media Schemas. `Specification.to_json()` returns a fresh source snapshot
with exact numeric contents. `ParameterContract.same_shape` compares non-Schema
fields; compare its separate `schema` field for Schema semantics.
`compat.Finding.witness` is `Some(value)` only for verified Schema counterexamples;
it is an added public record field in v0.9.0.

Use `openapi.parse_snapshot` and `diff.compare_snapshots` for source-value diffs;
`render_structural_text/json` optionally accept `summary=true`. The `schema` package
is independent of OpenAPI and I/O: `schema.parse`, `schema.subset(source, target)`
and `Schema.accepts(value)` expose the core operations. Existing authorization
parser and report interfaces are unchanged.

## Reference scope and interoperability

The reference is **oasdiff v1.35.0**, commit
`a4ba100f880c7579765c5e63915a99bf1acc6967`. It is a test oracle with no runtime
dependency. Its catalog has 778 changelog checks and 121 validation checks; the
nine local IDs aggregate a smaller, explicitly described set of behaviors.

| Reference capability | Current scope |
| --- | --- |
| Authorization | Independent policies with verified permission witnesses |
| General diff and summary | Entry-document values, including metadata; no reference expansion |
| Effective parameters and endpoint matching | Requiredness, removal and path-template identity |
| Request/response compatibility | Nine checks and the supported Schema assertions above |
| Consumer changelog, lifecycle/version policies | Not implemented |
| Full validation, composition and JSON Schema dialects | Not implemented |
| Schema flattening/upgrade, multi-file structural diff | Not implemented |
| Remote/Git input and upstream configuration surface | Not implemented; local loading only |
| Reports | Local text/JSON/SARIF APIs; upstream schemas are not emulated |

`compat/reference.py` checks 48 endpoint/parameter scenarios in four JSON/YAML
combinations (192 comparisons). `compat/schema_reference.py` checks 46
request/response scenarios in those combinations (184 comparisons): 3.0/3.1
nullability, types, enum changes, object requiredness, array items, components
and documentation-only edits. It checks manually specified verdicts and affected
operations, and retains both tools' findings. Generic local Schema IDs aggregate
several upstream rule IDs.

The oracle uses `--flatten-params` for effective parameters and `--fail-on ERR`
for confirmed breaks. The parameter matrix inventories the reference catalog;
checks outside that matrix are not implied to be covered. CI verifies the pinned
binary checksum and uploads both result files. Independent MoonBit tests also
enumerate 16129 finite enum policy pairs and check 576 object Schema pairs against
a separate finite-assignment evaluator.

```sh
python compat/reference.py --reference path/to/oasdiff --output parameter-results.json
python compat/schema_reference.py --reference path/to/oasdiff --output schema-results.json
```

Sources: [OpenAPI 3.0 Schema](https://spec.openapis.org/oas/v3.0.4.html#schema-object),
[OpenAPI 3.1 Schema](https://spec.openapis.org/oas/v3.1.1.html#schema-object),
[oasdiff commands](https://github.com/oasdiff/oasdiff/blob/v1.35.0/docs/README.md),
[check catalog](https://github.com/oasdiff/oasdiff/blob/v1.35.0/docs/CHECKS.md).
