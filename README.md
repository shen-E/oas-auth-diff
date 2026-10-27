# oas-auth-diff

Find authentication regressions between two OpenAPI documents, with a concrete
permission set that the new version accepts and the old version rejects.

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

## Use the library

The v0.1.0 package is prepared for release; it has not been uploaded to
Mooncakes. Until publication, place the consumer module and this checkout in
a separate parent directory, then create a workspace there:

```sh
moon work init consumer oas-auth-diff
```

Declare `shen-E/oas-auth-diff@0.1.0` in `consumer/moon.mod`; the workspace resolves
it to the checkout. After release, the registry dependency will be
`shen-E/oas-auth-diff@0.1.0` and the CLI package will be
`shen-E/oas-auth-diff/cmd/oas-auth-diff@0.1.0`.

Import `shen-E/oas-auth-diff/openapi` and `shen-E/oas-auth-diff/diff` in your
package. Parse each document with `parse_document(text, format=Json)`
or `format=Yaml`, then pass both documents to `compare`. The returned
`Comparison` exposes changes, diagnostics, completeness, and `exit_code()`.
`render_text`, `render_json`, and `render_sarif` render the same result.

The independent `shen-E/oas-auth-diff/logic` package supports positive
authorization policies, implication, permission evaluation, and counterexample
generation without OpenAPI or filesystem dependencies.

## Supported analysis

- OpenAPI 3.0 and 3.1 `paths` HTTP operations, in JSON or YAML.
- Global inheritance, operation overrides, anonymous alternatives, AND/OR
  requirements, OAuth/OpenID scopes, and OpenAPI 3.1 role names.
- Internal document references for relevant path items and security schemes.
- Equivalent, strengthened, weakened, and mixed changes. Mixed changes fail the
  gate when they admit a new access condition.

Operations match by exact HTTP method and path. Additions and removals are listed
separately; added anonymous operations receive a nonblocking review notice.
Scheme renames or changed authentication configuration make the affected
comparison incomplete. Description and presentation hints do not affect it.

External authentication references, callbacks, webhooks, server behavior, and
request/response compatibility are outside this analysis. Full input rules,
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
