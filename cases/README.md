# Example pairs

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
