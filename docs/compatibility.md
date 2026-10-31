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
| `response-success-status-removed` | An explicitly declared 2xx status is removed |
| `response-header-required-removed` | A guaranteed response header is removed |
| `response-header-became-optional` | A guaranteed response header becomes optional |
| `response-header-schema-widened` | A new header value is rejected by the previous Schema |

Request comparison proves **old instances are included in new instances**;
response comparison proves **new instances are included in old instances**.
The pure `schema` package supports types (including integer/number inclusion),
enums with exact decimal equality, nested object properties and requiredness,
`additionalProperties`, and array `items`. OpenAPI 3.0 `nullable` applies only
with an explicit type; 3.1 type unions and boolean schemas are supported.
Enum, required-name and type-array order do not change compatibility.
`allOf` applies the intersection of its branches, `anyOf` their union, and
`oneOf` requires exactly one matching branch, including overlap rejection.
Positive object constraints are intersected with each branch's own
`additionalProperties` rule. Branch order does not change semantics.
OpenAPI 3.1 `const`, local `$defs` and assertion siblings beside Schema `$ref`
are supported. Disjoint tagged unions can be proved using required discriminator
properties expressed as enum/const values; the `discriminator` keyword itself
is not interpreted.

Numeric `minimum`/`maximum` and exclusive bounds use exact decimal ordering,
including adjacent large integers and values smaller than binary floating-point
precision. OpenAPI 3.0 uses boolean exclusive flags; 3.1 uses numeric exclusive
bounds. Integer inclusions round boundaries according to the accepted integer
set. `minLength`/`maxLength` count Unicode scalar values, and `minItems`/`maxItems`
and `minProperties`/`maxProperties` constrain collection sizes. Assertions only
apply to their corresponding instance types. These constraints intersect through
`allOf` and participate in nested-property/item witnesses.

The inclusion algorithm returns a proof, a counterexample or Unknown. Each
counterexample is checked with a separate instance evaluator. Failure to prove
inclusion alone never becomes a finding. Schema parsing/comparison have
20000-step budgets; Schema and instance nesting is limited to 128. Exhaustion
produces an incomplete result.
Size-bound witness seeds use at most 4096 characters/items/properties; decimal
neighbour construction uses at most 4096 coefficient digits. Required properties
and supplied enum/const instances retain their normal input/step limits. Large limits can
still be evaluated and compared exactly. If no bounded witness or inclusion proof
is available, the result is incomplete.

Unsupported Schema assertions produce diagnostics even when present on both
sides. These include `multipleOf`, patterns, formats,
defaults, readOnly/writeOnly behavior, discriminators, dynamic references and
custom dialects. Some infinite compositions also remain undecided within the
proof budget. This is a bounded
checker, not a complete JSON Schema inclusion solver.
The standard 2020-12 and bundled OpenAPI dialects can be declared explicitly.
Supplying a custom dialect to `validate` checks Schema syntax; it does not teach
the compatibility solver new assertion semantics. A custom global dialect makes
`breaking` incomplete even when the declaration is unchanged.

Path-level parameters are inherited; operation declarations override them by
`(in, name)`. Header names compare without case and reserved header parameters
are ignored as required by OpenAPI. Path declarations must match their template
and be required. Template parameter renames preserve matching by position.

Parameter, body, response, Path Item and nested Schema references use the bounded,
caller-controlled local source graph. `--local-refs`/`--ref-root` retain their
directory confinement. Components can be renamed or inlined without changing a
resolved Schema. Recursive Schemas, assertion siblings beside a 3.0 Schema `$ref`,
`$id` resource scopes, unavailable targets and unresolved link references
produce diagnostics. References inside example data are not loaded. Locations
identify the actual referenced Schema resource without invented line numbers.

Media type names compare without case. Wildcards and media type parameters require
range matching and are incomplete. Response links, parameter/header serialization
changes, removed parameters, removed request bodies,
and other changed document/operation fields remain unclassified. Response
descriptions and Schema documentation edits do not create breaks. Authentication
changes belong to `compare`; run both semantic gates in CI.

Response selection uses concrete status > range (`2XX`) > `default`. Each pair
of effective declarations is compared once across HTTP statuses 100–599, so a
range change does not produce hundreds of duplicate results. Removing an
explicit 2xx declaration is a break even when a range/default remains; this
follows the reference tool's status-contract rule. Other status additions and
non-success deletions are not breaking by themselves, while changed effective
bodies/headers are still compared.

Response headers compare without case; required defaults to false. Removing an
optional header or adding a new header does not remove a guarantee. Schema and
single-media content header definitions use the same response inclusion
direction, retain reference origins and reject duplicate names. `Content-Type`
header declarations are ignored as specified by OpenAPI. See
[validation](validation.md) for independent official metaschema checks.

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
13 local IDs aggregate a smaller, explicitly described set of behaviors.

| Reference capability | Current scope |
| --- | --- |
| Authorization | Independent policies with verified permission witnesses |
| General diff and summary | Entry-document values, including metadata; no reference expansion |
| Effective parameters and endpoint matching | Requiredness, removal and path-template identity |
| Request/response compatibility | 13 checks and the supported Schema assertions above |
| Consumer changelog, lifecycle/version policies | Not implemented |
| Specification validation | Offline metaschemas, typed reference targets, registered dialects and paths cross checks; see validation scope |
| General Schema inclusion and custom dialects | Unsupported assertions and undecided compositions remain incomplete |
| Schema flattening/upgrade, multi-file structural diff | Not implemented |
| Remote/Git input and upstream configuration surface | Not implemented; local loading only |
| Reports | Local text/JSON/SARIF APIs; upstream schemas are not emulated |

`compat/reference.py` checks 48 endpoint/parameter scenarios in four JSON/YAML
combinations (192 comparisons). `compat/schema_reference.py` checks 138
request/response scenarios in those combinations (552 comparisons): 3.0/3.1
nullability, types, enum changes, object requiredness, array items, components
composition, numeric/size bounds and documentation-only edits. It checks manually specified verdicts and affected
operations, and retains both tools' findings. Generic local Schema IDs aggregate
several upstream rule IDs.

The oracle uses `--flatten-params` for effective parameters and `--fail-on ERR`
for confirmed breaks. The Schema matrix also enables `--flatten-allof` to compare
combined constraints; without it the reference downgrades some branch edits to
warnings. `compat/response_reference.py` adds 36 status/header scenarios in four
format combinations (144 comparisons). `validation/reference.py` checks 50
validation scenarios in JSON and YAML (100 comparisons), including typed targets
and recursive Schemas, retaining upstream loader errors separately from parsed
violations. These four matrices total 988 comparisons. Eight Schema comparisons
record an expected difference: v1.35.0 treats the 3.1 `exclusiveMinimum: 3` /
`minimum: 3` switch as separate bound removal/addition, while this tool checks
instance inclusion. The request relaxation and response restriction pass here;
the reference reports a break. Both verdicts are asserted in the matrix rather
than removing these cases or claiming identical behavior.

The parameter matrix inventories the reference catalog;
checks outside that matrix are not implied to be covered. CI verifies the pinned
binary checksum and uploads the four comparison matrices and independent witness results. Independent MoonBit tests also
enumerate 16129 finite enum policy pairs and check 576 object Schema pairs against
a separate finite-assignment evaluator, plus 2304 finite composition pairs
against an independent bit-set truth table and 225 small integer interval pairs.
`compat/witness_reference.py` uses Python `jsonschema==4.25.1` independently to
check all 64 emitted witnesses across the 138 Schema cases. JSON numbers in
witnesses are parsed as Decimal, and 3.0 nullable types are adapted explicitly.

```sh
python compat/reference.py --reference path/to/oasdiff --output parameter-results.json
python compat/schema_reference.py --reference path/to/oasdiff --output schema-results.json
python compat/response_reference.py --reference path/to/oasdiff --output response-results.json
python validation/reference.py --reference path/to/oasdiff --output validation-results.json
python -m pip install jsonschema==4.25.1
python compat/witness_reference.py --output witness-results.json
```

Sources: [OpenAPI 3.0 Schema](https://spec.openapis.org/oas/v3.0.4.html#schema-object),
[OpenAPI 3.1 Schema](https://spec.openapis.org/oas/v3.1.1.html#schema-object),
[JSON Schema numeric and size assertions](https://json-schema.org/draft/2020-12/json-schema-validation),
[oasdiff commands](https://github.com/oasdiff/oasdiff/blob/v1.35.0/docs/README.md),
[check catalog](https://github.com/oasdiff/oasdiff/blob/v1.35.0/docs/CHECKS.md).
