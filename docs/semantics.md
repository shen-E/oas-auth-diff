# Authentication comparison semantics

## Effective requirements

Analysis covers the HTTP operations directly exposed through `paths` in OpenAPI
3.0.x and 3.1.x. An absent operation `security` inherits the root declaration.
An absent root declaration, an empty security array, or an empty requirement
object permits anonymous access. Array entries are alternatives (OR). Schemes
inside one object must all be satisfied (AND). Each scheme's listed scopes must
all be present. These rules follow the OpenAPI [Security Requirement
Object](https://spec.openapis.org/oas/v3.1.1.html#security-requirement-object).

OAuth2 and OpenID Connect requirements use literal scope names. Other schemes
require empty arrays in 3.0; 3.1 may specify literal required role names. Role
hierarchies and implicit application grants are not inferred. A scope or role
atom implies possession of its named scheme's credential.

Policies normalize to disjunctions of conjunctions. Duplicate atoms and
alternatives are removed, as are alternatives subsumed by a less restrictive
one. An empty conjunction is anonymous access; no alternatives accepts nothing.

## Inclusion and witnesses

The candidate policy implies the baseline exactly when every candidate
alternative contains all the atoms of at least one baseline alternative. If a
candidate alternative contains none of the baseline alternatives, its atoms form
a witness: the candidate accepts those grants and the baseline rejects them.
The comparison verifies every generated witness by evaluating both policies.

Both implication directions distinguish equivalent, strengthened, weakened,
and mixed changes. A mixed change both grants and removes access conditions.
Weakened and mixed operations fail the gate because each has a new accepted
permission set. Runtime comparison uses normalized subset tests, not assignment
enumeration. Tests independently enumerate all assignments for small policies.

Method and path identify an operation; `operationId` is only a label. Path
renames appear as removal and addition. New anonymous operations are review
notices, with no regression exit code by themselves.

## Scheme identity and completeness

The same declared scheme name must have the same authentication fingerprint in
both documents for an affected operation to be compared. Relevant API-key
name/location, HTTP scheme, OAuth flow endpoints, and OpenID URL are part of
that identity. Descriptions, bearer-format hints, scope descriptions, and
ordering are not. Renamed or missing declarations are not automatically paired.
OAuth authorization/token/refresh endpoints and the OpenID URL must be absolute
HTTP or HTTPS URLs. Relative authentication URLs depend on server resolution and
make affected operations incomplete in v0.1. An unused invalid declaration does
not block analysis.
Even a removed requirement is conservatively incomparable if its scheme has
no matching declaration in the other document.

A diagnostic marks analysis incomplete and gives exit code 2 priority. Findings
on other operations remain available. This avoids treating malformed or
unsupported authentication as a successful check.

## Input boundaries

JSON rejects duplicate decoded object keys. YAML uses the pinned
`moonbitstack/moonyaml@0.1.2` parser with YAML 1.2 core semantics, exactly one
document, and tags, anchors, and aliases disabled. Mappings require string keys.
Decoded duplicate keys and plain merge keys (`<<`) are rejected. YAML nodes are
converted explicitly without a generic JSON conversion that could coerce keys.
Nonfinite numbers are rejected in either format. Unrelated example numbers
have no effect on authorization calculations.

Limits apply to each input: 16 MiB encoded UTF-8, 128 nesting levels, and 250,000
nodes. Each operation permits at most 256 security alternatives, 1,024 atoms
per alternative, and 8,192 total atoms before normalization. Exceeding a limit
produces a diagnostic instead of omitting requirements.
The native CLI opens regular files, checks size on the open handle, and reads
at most 16 MiB plus one detection byte. File growth after the size check cannot
cause an unbounded read.

Only relevant path-item and security-scheme references are resolved. References
must be document-local JSON Pointers beginning with `#/`. Invalid pointers,
cycles, conflicting referenced path-item definitions, and external references
on an analyzed path are errors. External response schemas do not block the
authentication check because they are never traversed. No network requests are
made during analysis. Callback and webhook operations are not included.
Operation-object references are not part of OpenAPI's operation structure and
are rejected. OAuth scopes must be declared by at least one flow of the named
scheme. YAML directives must select version 1.2.

Locations carry the source URI and an RFC 6901 JSON Pointer. Syntax errors retain
available parser line and column information in diagnostics. Reports do not
fabricate line numbers for resolved nodes.
