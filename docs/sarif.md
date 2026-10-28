# SARIF in CI

Generate a SARIF 2.1.0 report with the checkout root:

```sh
oas-auth-diff compare specs/before.yaml specs/after.yaml --format sarif --source-root "$PWD" > auth-diff.sarif
```

`--source-root` requires an existing directory and `--format sarif`. It changes
report locations, without enabling file references or changing their loading
boundary. Use `--local-refs` or `--ref-root` separately when the specifications
require local files. Exit codes remain 0 for complete/no regression, 1 for a
verified regression, and 2 for incomplete analysis or an error.

## File locations

A safe file URI inside the root becomes a relative `artifactLocation.uri`
with `uriBaseId: "%SRCROOT%"`. The run records the directory URI in
`originalUriBaseIds["%SRCROOT%"]` and `invocations[0].workingDirectory`.
For example, `file:///checkout/specs/after.yaml` becomes `specs/after.yaml`.
Files outside the root retain their absolute URIs without a base id. Source
labels and other URI schemes keep their existing representation.

The mapping compares complete path segments, preserves path case, and never
percent-decodes a separator before checking containment. Escaped filename
characters stay escaped. A first segment containing a colon gains `./` so it
remains a relative reference. Ambiguous encoded separators and dot segments
are not rewritten. The library performs URI processing without filesystem I/O;
this option is not a file-access boundary.

`properties.source` and `properties.jsonPointer` retain the original evidence.
JSON/text reports and parsed document sources are unchanged by the option.
CLI failures before a comparison is constructed use the default failure
report: they omit source-root metadata and keep their original locations.
The library accepts an absolute local directory file URI through
`SarifSourceRoot::new`; it rejects unsupported authorities, query strings,
fragments, malformed escapes, and unsafe path segments. `root.uri()` returns
the normalized directory URI, including its trailing slash.

GitHub interprets relative locations from the repository root, so use that
directory when preparing an upload. Files outside the checkout may not map
to repository files. GitHub uploads with a file source root also require
physical artifact locations to use the file scheme. Reports contain file locations and JSON Pointers;
they do not fabricate line regions. Inline pull-request annotations therefore
depend on the consumer's support for file-level findings. See GitHub's
[source-location rules](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support#source-file-locations).

## Stable result identities

Results with a valid local-file entry source include two equal SHA-256 values
in `partialFingerprints`: `oasAuthDiff/route/v1` and
`primaryLocationLineHash`. The latter is the property consumed by GitHub.
Despite that property's name, this tool hashes operation identity rather than
a source line. The recipe is a fixed JSON array containing a version marker,
rule id, candidate entry identity, exact HTTP method, and path-template
identity. The digest is lowercase hexadecimal.

With a source root, an entry inside it uses a relative identity, so moving an
unchanged checkout preserves its fingerprints. An entry outside it uses its
full normalized file URI. Without a root, absolute entry URIs remain part of
the identity. Different entry documents remain distinct even when they share
one external security declaration and expose the same method and route.

Parameter names, `operationId`, witnesses, change categories, deployment URLs,
and the location of the security declaration do not enter the hash. Renaming a
path parameter or changing the selected witness therefore preserves the result
identity. Rules, methods, literal route segments, and entry identities do
distinguish findings. Missing sources, source labels, and non-file entry URIs
omit fingerprints rather than guessing an analysis target.

`Comparison.before_source` and `after_source` carry the original entry sources;
`compare` copies them from its input documents. Fatal `failure_report` values
use `None` on both sides. JSON and SARIF properties expose
`document_sources: {before, after}` as strings or `null`, retaining
`schema_version: 1`. Library callers constructing a `Comparison` directly must
supply both fields.

The output format and identity rules are verified locally. GitHub's documented
[fingerprint handling](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support#data-for-preventing-duplicated-alerts)
and [custom-fingerprint guidance](https://github.com/github/codeql-action/issues/986)
describe ingestion; this release has not uploaded repeated analyses to verify
server-side alert matching.

## Keep the comparison exit code

After your workflow has made the CLI available on `PATH`, the following steps
preserve the comparison's result while allowing the report to be uploaded.
The job needs `contents: read` and `security-events: write`; private repositories
also need `actions: read`. Replace the input paths and choose a category that
stays constant for the same API pair. See GitHub's
[upload instructions](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

```yaml
- name: Compare API authentication
  id: auth
  shell: bash
  run: |
    status=0
    oas-auth-diff compare specs/before.yaml specs/after.yaml \
      --format sarif --source-root "$GITHUB_WORKSPACE" > auth-diff.sarif || status=$?
    echo "status=$status" >> "$GITHUB_OUTPUT"
- uses: github/codeql-action/upload-sarif@v4
  if: always() && steps.auth.outputs.status != ''
  with:
    sarif_file: auth-diff.sarif
    category: oas-auth-diff/api
- name: Enforce authentication comparison
  if: always() && steps.auth.outputs.status != ''
  shell: bash
  run: exit "${{ steps.auth.outputs.status }}"
```

Uploading a report does not replace the exit-code gate. Incomplete comparisons
remain failures even when the same report contains independently verified
regressions. An unsuccessful upload also remains a failed workflow step.
