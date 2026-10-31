# Example pairs

`account.before.yaml` and `account.after.json` share a component between request
and response. Removing `id.readOnly` makes the request's `id` required; adding
`token.writeOnly` lets the response omit `token`. The name pattern also narrows
from lowercase letters to `a`–`f`. The directional-requiredness profile reports
request and response witnesses, while retaining constraints on present fields:

```sh
oas-auth-diff breaking cases/account.before.yaml cases/account.after.json --format json
```

The unchanged `int64` format is an annotation in this profile, so it does not
impose an integer range. A format label change would make comparison incomplete.

`bounds.before.yaml` accepts export requests with a limit up to 100, labels up to
80 characters and up to 20 field names. `bounds.after.json` tightens each request
limit and widens the integer response from 100 to 200. `breaking` returns exit 1
with request and response instance witnesses:

```sh
oas-auth-diff breaking cases/bounds.before.yaml cases/bounds.after.json --format json
```

`dialect.yaml` uses an explicitly registered 2020-12 extension for field
classification. Its `x-sensitivity` annotation must be `public` or `private`.
Changing it to `secret` produces a validation violation at the field location:

```sh
oas-auth-diff validate cases/dialect.yaml --dialect https://example.test/sensitivity=cases/sensitivity.json
```

`orders.before.yaml` requires both `orders:read` and `orders:write`.
`orders.after.json` removes the write requirement. Comparing them returns exit
code 1 and a witness with the account credential and only the read scope.

`oauth-relative.before.yaml` resolves `token` against an absolute server URL.
`oauth-relative.after.json` spells the same token endpoint as an absolute URL
and removes `stock:write`. Comparing them returns exit code 1, with a warehouse
credential and the read scope. Changing only the spelling of that URL preserves
the credential identity.

`paired-schemes/before.yaml` requires a bearer session and a deployment gate
key. `paired-schemes/after.json` removes the gate requirement but still declares
its identity through `schemes.json`. The paired parser loads that related
definition on both sides and verifies a witness with only the session:

```sh
oas-auth-diff compare cases/paired-schemes/before.yaml cases/paired-schemes/after.json --local-refs
```

`path-parameters.before.yaml` protects a deployment-details route with a bearer
session. `path-parameters.after.json` renames both path parameters and adds an
anonymous operation override. The route's literal structure is unchanged, so
the comparison returns one weakened operation, an empty credential witness,
and exit code 1. Reports retain both original path spellings:

```sh
oas-auth-diff compare cases/path-parameters.before.yaml cases/path-parameters.after.json
```

`payload.before.yaml` accepts draft or confirmed orders and guarantees an integer
response `id`. `payload.after.json` accepts only confirmed orders and makes `id`
optional. `breaking` reports a request narrowing witness and a response widening
witness; `diff` also exposes the documentation version and source-value edits:

```sh
oas-auth-diff breaking cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff diff cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff summary cases/payload.before.yaml cases/payload.after.json
```

The Petstore pair adapts the OpenAPI Initiative's [Petstore sample at commit
4f86429f134f7e48b6351563549b4502fc69de52](https://github.com/OAI/OpenAPI-Specification/blob/4f86429f134f7e48b6351563549b4502fc69de52/_archive_/schemas/v3.0/pass/petstore.yaml).
The upstream repository distributes its source under Apache-2.0; see the
[upstream license](https://github.com/OAI/OpenAPI-Specification/blob/4f86429f134f7e48b6351563549b4502fc69de52/LICENSE).
The sample's `info.license` describes the example API itself.

Local modifications add an `apiKey` security scheme to both files. The protected
version requires it globally; the public version uses `security: []`. Comparing
protected to public detects anonymous access for all three existing operations.
All response schemas and examples remain available to exercise a normal API
document without dereferencing irrelevant schemas.
