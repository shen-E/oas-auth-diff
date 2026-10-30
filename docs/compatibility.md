# Endpoint and parameter compatibility

`breaking` checks existing operations for endpoint removal, newly required
query/header/cookie parameters, and optional parameters becoming required.
These changes can reject requests that satisfied the previous contract.
`compare` continues to check authorization regressions independently.

```sh
oas-auth-diff checks --format json
oas-auth-diff breaking cases/parameters.before.yaml cases/parameters.after.json
oas-auth-diff breaking cases/parameters.before.yaml cases/parameters.after.json --format json
oas-auth-diff breaking cases/parameters.before.yaml cases/parameters.after.json --format sarif --source-root .
```

The example adds the required `tenant` query parameter and exits 1. Repeating
one input exits 0; malformed parameters, unavailable references or unclassified
contract changes exit 2. JSON reports identify `report_kind: "compatibility"`,
the analysis scope and the exact `checked_rules`. `complete` refers to that
profile, not full OpenAPI validation or full oasdiff compatibility.

| Check | Trigger |
| --- | --- |
| `endpoint-removed` | An existing method/path-template identity disappears |
| `request-parameter-added-required` | A matched operation gains a required non-path parameter |
| `request-parameter-became-required` | A matched operation's parameter changes from optional to required |

Path-level parameters are inherited, and operation declarations override them
by `(in, name)`. Duplicate declarations within one list are errors. Header
names compare without case; OpenAPI's ignored `Accept`, `Content-Type` and
`Authorization` header parameter declarations do not introduce requirements.
Path parameter declarations must agree with the template and be required;
renaming a template parameter preserves operation matching. A required default
does not make the parameter optional.

Parameter and Path Item references use the existing local reference loader and
budgets. `--local-refs` and `--ref-root` retain their directory confinement.
Schema/content/response references are not resolved by this profile and make
the affected operation incomplete. This prevents a referenced contract from
changing outside the fields observed by the checker.

Changed parameter schemas, serialization, removed parameters, document-level
contract fields or other operation fields are reported as unclassified rather
than clean compatibility. Confirmed findings survive an incomplete result.
Optional parameter additions with defaults are also unclassified. Structural
metadata handling is deliberately conservative: for example, edits inside a
response description can still require review. Authentication changes remain
the responsibility of `compare`; run both gates when both policies matter.

## Library

Parse each input with `openapi.parse_specification`, optionally supplying a
caller-controlled loader, then call `compat.compare`. Existing authentication
document types and parser signatures are unchanged. `Specification.to_json()`
returns a fresh snapshot, including request/response bodies and Schema fields
not yet classified by this profile. Number representations are retained;
JSON's `as_number` still returns a rounded Double. YAML numeric spellings are
converted to exact JSON decimal representations without a Double round-trip.

## Reference scope

The reference is **oasdiff v1.35.0**, commit
`a4ba100f880c7579765c5e63915a99bf1acc6967`. The MoonBit implementation runs
independently; oasdiff is a test oracle, not a runtime dependency.

| Reference capability | Current implementation |
| --- | --- |
| Authorization semantics | Independent policy comparison with verified access witnesses |
| Effective parameters and endpoint matching | Implemented for the profile above |
| Backward compatibility rules | The three checks listed above; remaining rules are not implemented |
| General diff, summary and consumer changelog | Not implemented |
| Request/response Schema compatibility | Not implemented; changed observed fields are unclassified |
| Full validation and OpenAPI 3.1 keyword handling | Not implemented; input and parameter checks are not a complete validator |
| Schema flattening, upgrade and lifecycle/version policies | Not implemented |
| Remote/Git input, composed specs and upstream configuration options | Not implemented; local loader controls apply |
| Output | Text, JSON and SARIF; upstream output schemas and exit codes are not emulated |

The rule list is explicit and is not a claim of feature parity with the
reference. The pinned reference's complete catalog is available with
`oasdiff checks changelog --format json` and `oasdiff checks validate --format json`.
The v1.35.0 catalogs contain 778 changelog checks and 121 validation checks.

`compat/reference.py` compares manually specified breaking/nonbreaking cases
against that version, including OpenAPI 3.0/3.1, inheritance, component references
and header case. It checks the verdict, mapped rules and affected operations,
and records all differences. The reference runs with `--flatten-params` so both
tools compare effective inherited parameters, and `--fail-on ERR` to compare
confirmed breaks. Original paths remain in the report; matching uses template
identity. It does not test the other reference checks.

The matrix has 48 semantic scenarios across four JSON/YAML input combinations.
The result also inventories every reference check, distinguishing profile-only
counterparts from checks that are not implemented.

```sh
python compat/reference.py --ours path/to/oas-auth-diff --reference path/to/oasdiff --output reference-results.json
```

The upstream counterparts are `api-path-removed-without-deprecation`,
`new-required-request-parameter`, and `request-parameter-became-required`.
Our IDs and output format are separate APIs.

Sources: [reference commands](https://github.com/oasdiff/oasdiff/blob/v1.35.0/docs/README.md),
[check classification](https://github.com/oasdiff/oasdiff/blob/v1.35.0/docs/CHECKS.md).
