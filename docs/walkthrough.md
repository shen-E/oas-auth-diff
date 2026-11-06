# Review an API change

Install the release, clone the repository for the example specifications and run
these commands from the checkout root:

```sh
moon install shen-E/oas-auth-diff/cmd/oas-auth-diff@0.14.0
git clone https://github.com/shen-E/oas-auth-diff.git
cd oas-auth-diff
oas-auth-diff --version
```

## Inspect the edits

```sh
oas-auth-diff diff cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff summary cases/payload.before.yaml cases/payload.after.json
```

Both commands exit 0 after enumerating changes. Reviewers can inspect the
source-value edits before choosing the semantic gates.

## Review access and client contracts

```sh
oas-auth-diff compare cases/orders.before.yaml cases/orders.after.json --format json
oas-auth-diff breaking cases/payload.before.yaml cases/payload.after.json --format json
oas-auth-diff breaking cases/labels.before.yaml cases/labels.after.json --format json
```

These commands intentionally exit 1. The first comparison removes the write
scope from an existing operation. The payload example narrows request values
and removes a guaranteed response field. The label example resolves a static
Schema anchor and narrows a BMP character language. Read `witness` and
`witness_verified` in compatibility findings; evaluate the witness against the
two Schemas when integrating another consumer.

Reversing the label inputs exits 0 because the previously accepted requests
remain accepted. A changed format label or unsupported Schema assertion can
instead make a semantic comparison incomplete and exit 2. Such a report can
still contain independently established findings.

## Check the specifications

```sh
oas-auth-diff validate cases/labels.before.yaml --format json
oas-auth-diff validate cases/labels.after.json --format json
oas-auth-diff validate cases/payload.before.yaml --format json
```

These inputs exit 0 after the implemented document and reference checks.

## Produce a CI report

```sh
oas-auth-diff compare cases/orders.before.yaml cases/orders.after.json --format sarif --source-root . > auth.sarif
```

The expected exit is 1 and `auth.sarif` contains the finding. Keep that exit code
when uploading the report; [SARIF in CI](sarif.md) shows the gate. The manual
OpenAPI reports workflow exercises upload categories for authorization and Schema
compatibility using these fixtures. Its success means the known example exits
and report upload succeeded, not that the example APIs have no findings.
