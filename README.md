# oas-auth-diff

Find authentication regressions between two OpenAPI documents, with a concrete
permission set that the new version accepts and the old version rejects.

`diff` and `summary` inspect general entry-document changes, including metadata.
`breaking` checks endpoint/parameter contracts and request/response Schema
compatibility, with concrete data witnesses for Schema breaks. See
[compatibility scope](docs/compatibility.md) for the 13 checks, supported Schema
assertions, unresolved fields and the pinned oasdiff v1.35.0 reference.
`validate` checks OpenAPI objects and reference targets against offline
metaschemas, with paths cross checks and explicit dialect registration. See [validation](docs/validation.md) for supported dialects,
reference handling and the pinned MoonBit validation dependency.

For example, changing an operation from requiring `orders:read` **and**
`orders:write` to requiring only `orders:read` produces a witness with the account
credential and the read scope. This makes the reason for a CI failure inspectable.

## Install and compare

Use a current MoonBit toolchain. This version is tested with
`moon 0.1.20261023` / `moonc v0.10.17`; CI records its toolchain version.

```sh
git clone https://github.com/shen-E/oas-auth-diff.git
cd oas-auth-diff
moon install ./cmd/oas-auth-diff
oas-auth-diff compare cases/orders.before.yaml cases/orders.after.json
oas-auth-diff compare cases/orders.before.yaml cases/orders.after.json --format json > auth-diff.json
oas-auth-diff compare cases/orders.before.yaml cases/orders.after.json --format sarif > auth-diff.sarif
oas-auth-diff compare cases/orders.before.yaml cases/orders.after.json --format sarif --source-root . > auth-diff.sarif
oas-auth-diff compare before/api.yaml after/api.yaml --local-refs
oas-auth-diff compare cases/paired-schemes/before.yaml cases/paired-schemes/after.json --local-refs
oas-auth-diff breaking cases/parameters.before.yaml cases/parameters.after.json --format json
oas-auth-diff breaking cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff diff cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff summary cases/payload.before.yaml cases/payload.after.json
oas-auth-diff checks --format json
oas-auth-diff validate cases/payload.before.yaml --format json
```

Build the native CLI from a checkout:

```sh
moon run cmd/oas-auth-diff --target native -- compare cases/orders.before.yaml cases/orders.after.json
```

| Exit | Meaning |
| --- | --- |
| 0 | Analysis completed without new access conditions on existing operations. |
| 1 | A verified witness demonstrates weaker authentication. |
| 2 | Input error or incomplete comparison; any findings already established remain in the report. |

Reports go to stdout and diagnostics to stderr. JSON reports include
`schema_version: 1`, completeness, operation changes, normalized requirements,
witnesses, diagnostics, and source locations. SARIF 2.1.0 uses file URIs and JSON
Pointers; it does not infer line numbers.

Local specifications with relative servers can declare where each document is
expected to be served:

```sh
oas-auth-diff compare before.yaml after.yaml --before-document-url https://api.example/spec/openapi.yaml --after-document-url https://api.example/spec/openapi.yaml
```

These are complete document URLs. For example, `servers: [{url: ../api/}]`
resolves against `/spec/openapi.yaml` to `/api/`. The options supply resolution
context and make no network requests. They do not enable local references or
change their directory boundary. File URIs remain the evidence locations.
JSON `document_urls` and SARIF run properties record the normalized before/after
entry URLs; text reports show the same context. Fatal load/parse reports have
no parsed URL context.

`--local-refs` enables referenced JSON/YAML files inside each entry file's
directory. `--ref-root DIR` enables them within an explicit shared directory.
Nested references resolve relative to the file containing the reference;
percent-encoded filenames are decoded once. Network references, symlinks,
Windows reparse points, and files outside the boundary are rejected. Entry
files themselves are explicitly selected inputs and need not lie inside
`--ref-root`. With neither option, references stay within the current document.

## Use the library

The v0.11.0 package is prepared for release; it has not been uploaded to
Mooncakes. Until publication, place the consumer module and this checkout in
a separate parent directory, then create a workspace there:

```sh
moon work init consumer oas-auth-diff
```

Declare `shen-E/oas-auth-diff@0.11.0` in `consumer/moon.mod`; the workspace resolves
it to the checkout. After release, the registry dependency will be
`shen-E/oas-auth-diff@0.11.0` and the CLI package will be
`shen-E/oas-auth-diff/cmd/oas-auth-diff@0.11.0`.

Import `shen-E/oas-auth-diff/openapi` and `shen-E/oas-auth-diff/diff` in your
package. Parse each document with `parse_document(text, format=Json)`
or `format=Yaml`, then pass both documents to `compare`. The returned
`Comparison` exposes changes, diagnostics, completeness, and `exit_code()`.
`render_text`, `render_json`, and `render_sarif` render the same result.
`Comparison.before_source` and `after_source` retain entry document identities;
JSON and SARIF expose them as `document_sources`.

For portable SARIF locations, construct
`SarifSourceRoot::new("file:///checkout/")` in the `diff` package and pass
`source_root=Some(root)` to `render_sarif`. The constructor raises `SarifError`
for an invalid directory URI. Existing render calls need no new arguments.
The CLI exposes this as `--source-root DIR` with `--format sarif`.
See [SARIF in CI](docs/sarif.md) for file mapping, stable result fingerprints,
and a workflow example.

For comparison inputs, `parse_pair(before_source, after_source)` returns a
`DocumentPair` with `before` and `after` documents. Each input is a
`SourceDocument` containing text, format, and canonical source identity.
Optional `before_load=Some(loader)` and `after_load=Some(loader)` enable
controlled file loading; `before_document_url` and `after_document_url` set
deployment context. Fatal `PairError.Before` and `PairError.After` distinguish
which input failed. Pass the returned documents to the same pure `compare`.

The CLI uses paired parsing. For each common method and path-template structure,
it resolves the scheme names used on either side, including a removed
requirement's still declared external definition. Thus removing one factor can
produce a verified regression instead of an unknown identity. Each side keeps
its own loader, cache, and resource limits. Unrelated unused external
definitions are not read.

For split specifications, use `parse_with_loader(text, format=Json,
source=entry_uri, load=loader)`. The loader receives the referring document's
canonical source URI and a decoded relative path without its fragment. It
returns `SourceDocument { text, format, source }`, or raises `DocumentError`.
Use a stable canonical `source` for caching, cycle detection, and report
locations. The caller controls file access; the core library performs no I/O.

Both parsers accept `document_url=Some("https://api.example/spec/openapi.yaml")`
to set a deployment address independently of `source`. With this option,
referenced documents inherit addresses resolved from their referring document's
URL and the original escaped reference path. A canonical source with conflicting
addresses is diagnosed; dependent policies are withdrawn. Without the option,
an HTTP(S) `source` remains its document's default address. `Document.document_url`
exposes the entry context, while `Document.source` retains its source identity.

The independent `shen-E/oas-auth-diff/logic` package supports positive
authorization policies, implication, permission evaluation, and counterexample
generation without OpenAPI or filesystem dependencies.

## Supported analysis

- OpenAPI 3.0 and 3.1 `paths` HTTP operations, in JSON or YAML.
- Global inheritance, operation overrides, anonymous alternatives, AND/OR
  requirements, OAuth/OpenID scopes, and OpenAPI 3.1 role names.
- Relative OAuth/OpenID endpoints resolved against effective HTTP(S) servers,
  with operation/path overrides and finite server-variable enumerations.
- Internal references and opt-in local files for relevant path items and
  security schemes, including mixed JSON/YAML reference chains.
- Targeted counterpart scheme resolution for common operations, sharing the
  input's existing snapshot and limits across all parsing phases.
- Equivalent, strengthened, weakened, and mixed changes. Mixed changes fail the
  gate when they admit a new access condition.

Operations match by exact HTTP method and path-template structure. Renaming
`/orders/{id}` to `/orders/{order_id}` keeps the operation in the comparison;
changing a literal path segment still appears as removal and addition.
`OperationChange.before_path` and `after_path` retain both spellings; the
existing `path` field names the candidate path, or the removed baseline path.
JSON and SARIF properties include both optional fields. Duplicate template
structures within one input are errors, even with different HTTP methods.
Additions and removals are listed separately; added anonymous operations receive
a nonblocking review notice. See the [parameter-renaming example](cases/README.md).
Scheme renames or changed authentication configuration make the affected
comparison incomplete. Description and presentation hints do not affect it.
Endpoint identities are resolved for each operation, so sharing a component
does not hide a different server override. Server order does not affect the
comparison. A relative server requires a configured document URL or an HTTP(S)
source URI. Variables used by a server must declare
a finite, nonempty `enum` containing their `default`.

Authorization comparison excludes network authentication references, callbacks,
webhooks, server behavior and request/response compatibility. The separate
`breaking` command checks the documented request/response contract profile. Input rules,
resource limits, and the implication algorithm are described in
[semantics](docs/semantics.md). [Example pairs](cases/README.md) include a pinned
OpenAPI Initiative sample.

## Develop

```sh
moon check --target all
moon test --target all
moon build cmd/oas-auth-diff --target native
python cmd/oas-auth-diff/smoke.py
moon fmt
moon info
```

The smoke check locates the built executable. CI runs the portable
library tests on all four backends and the native CLI checks on three operating
systems. Tests include an exhaustive small-model oracle for policy implication.

Apache-2.0. Dependencies and adapted examples retain their upstream licenses.
