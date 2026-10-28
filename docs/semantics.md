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

HTTP method and path-template structure identify an operation; `operationId`
is only a label. Renaming a path parameter preserves the match. Changing a
literal segment appears as removal and addition. New anonymous operations are
review notices, with no regression exit code by themselves.

## Path-template identity

OpenAPI treats templates at the same hierarchy with different parameter names
as [the same path](https://spec.openapis.org/oas/v3.1.1.html#path-templating-matching).
The shared `@openapi.path_identity(path)` helper replaces each nonempty `{name}`
with `{}`. Thus `/orders/{id}` and `/orders/{order_id}` have the same identity.
The comparison and paired scheme resolver use this identity with the exact
HTTP method. A parameter rename cannot turn an authentication change into an
unrelated addition and removal.

Literal text, case, slash positions, trailing slashes, and percent encodings
remain unchanged. Static paths and templated paths are distinct; the analyzer
does not guess between partially overlapping routes such as `/{entity}/me`
and `/books/{id}`. Templates embedded in literal segments are handled without
discarding those literals. Parameter declarations, schema constraints, and
framework-specific route syntax are not used to infer additional matches.

Paths must start with `/`. Empty parameters, nested or unbalanced braces, and
parameters crossing `/` are invalid and produce `auth.path`. The parser
detects multiple raw paths with the same template identity before resolving
their Path Items, reports `path-duplicate` at each original path, and skips
those paths. This applies even when the paths declare different HTTP methods
or one is empty. Unrelated paths retain their analysis results.

Pure `diff.compare` also checks documents constructed by library callers.
Repeated method/path declarations produce `operation-duplicate`; different raw
paths with one template identity produce `path-duplicate`. Affected groups are
incomparable and contribute no witness. Diagnostics make the result incomplete
with exit code 2, while independent verified regressions remain in the report.

`OperationChange.before_path` and `after_path` retain the original spellings,
with `None` on a genuinely absent side. The existing `path` remains the candidate
path when present, otherwise the removed baseline path. JSON reports and SARIF
result properties include `before_path` and `after_path` as strings or `null`;
these additive fields retain JSON `schema_version: 1`. Text and SARIF messages
show both paths when their spellings differ. Locations retain the actual source
URI and JSON Pointer of the relevant declaration.
Library callers constructing an `OperationChange` directly must supply both
path fields; an absent side uses `None`.

## Scheme identity and completeness

The same declared scheme name must have the same authentication fingerprint in
both documents for an affected operation to be compared. Relevant API-key
name/location, HTTP scheme, OAuth flow endpoints, and OpenID URL are part of
that identity. Descriptions, bearer-format hints, scope descriptions, and
ordering are not. Renamed or missing declarations are not automatically paired.
API-key header names compare without case; query and cookie names retain case.
OAuth authorization/token/refresh endpoints and the OpenID URL resolve to HTTP
or HTTPS URLs. An unused invalid declaration does not block analysis.
Even a removed requirement is conservatively incomparable if its scheme has
no matching declaration in the other document.
Single-document parsing does not load unused external definitions. Comparing
two independently parsed documents can therefore remain incomplete when a
removed requirement's matching identity exists only through an unused external
reference. Paired parsing resolves that comparison dependency explicitly.

A diagnostic marks analysis incomplete and gives exit code 2 priority. Findings
on other operations remain available. This avoids treating malformed or
unsupported authentication as a successful check.

## Paired input resolution

`parse_pair` accepts two `SourceDocument` inputs and returns a `DocumentPair`.
It prepares both inputs independently, matches method/path-template pairs whose
own authentication policies are valid, and takes each pair's used scheme-name
union. A side lacking an identity resolves its own declaration with its own
operation's effective servers. A scheme fingerprint is never borrowed from
the other input. Missing declarations, changed configurations, and invalid
definitions remain incomparable. Added and removed operations do not request
matching counterpart declarations.

The CLI uses this path automatically. Local file loading still requires
`--local-refs` or `--ref-root`; network references remain unsupported. Library
callers supply separate optional `before_load` and `after_load` callbacks and
deployment URLs. Fatal `PairError.Before` / `PairError.After` wrap the original
`DocumentError` without guessing an error location. Existing single-document
parsers retain their interfaces, and `diff.compare` performs no I/O.

Each input keeps one live source graph across normal extraction and counterpart
resolution. Successful and failed requests are cached; no phase re-reads or
re-parses an existing request. The graphs are separate, so the same canonical
URI can legitimately contain different before/after snapshots. Within one
graph, contradictory text or format for a canonical source is an error.

Counterpart lookup consumes the existing used-identity budget before unrelated
local unused work. Each actual missing-identity attempt costs at least one
tuple, including failures; a successful multi-server identity costs its full
tuple count. Document, byte, node, tuple, and serialized-identity limits do not
reset between phases or transfer between inputs. Exhaustion gives an incomplete
result and retains independent findings.

Finalization occurs after supplemental loading. Deployment-address conflicts
withdraw identities that depend on the ambiguous origin. Content conflicts
withdraw policies and identities whose reference chains read the contradictory
source, including anonymous policies and absolute authentication endpoints.
An independent path through a different reference chain keeps its valid
evidence. This prevents a late lookup from leaving an earlier untrustworthy
witness in the report.

## Relative authentication addresses

Endpoint resolution follows [OpenAPI's relative API URL
rules](https://spec.openapis.org/oas/v3.1.1.html#relative-references-in-api-urls).
For each operation, its `servers` overrides the path item's list, which in turn
overrides the entry document's list. An absent or empty effective list supplies
the default `/` server. Referenced path items retain the source of their server
declaration. Relative servers require an HTTP(S) retrieval URI for that
declaration. A configured document URL supplies this origin independently of the
source identity; an unconfigured CLI `file:` URI produces `auth.base`. There is
no network discovery.

For relative endpoints, each effective server generates a complete tuple of
OAuth flow addresses or an OpenID address. The tuple set is sorted and
deduplicated. Equivalent absolute/relative spellings and reordered servers
compare equally. A changed endpoint set remains incomparable, rather than
being interpreted as a permission change. Absolute endpoints do not depend
on server declarations. `Operation.scheme_identities` exposes the resolved
credentials used by comparison; document-level declarations alone do not
capture operation-specific server overrides.

Every variable used in a server URL requires a string `default` and a nonempty
string `enum` containing it. All combinations are expanded, and the default
combination is retained in the identity. Changing an enum domain or its default
can therefore change identity. Unrestricted variables produce `auth.variable`;
the analyzer does not substitute only the default and call the whole domain
equivalent.

URL resolution uses RFC 3986 path merging and dot-segment removal. Scheme and
host case, default ports, IPv6 spelling, and percent-escape hex case are
normalized. Reserved percent escapes remain encoded. Supported authorities
are ASCII DNS/IDNA names, IPv4, and bracketed IPv6. User information, fragments,
raw Unicode, scoped IPv6, IPvFuture, spaces, controls, malformed escapes,
backslashes, and non-HTTP schemes produce `auth.url` diagnostics.

Expansion allows 16 variables per server and 64 server variants per operation.
An entry permits 100,000 used scheme/server tuple instances, charged even when
cached. URI text is limited to 8,192 UTF-8 bytes, one resolved identity to 1 MiB,
and the entry's used identity strings to 32 MiB. Exceeding these limits marks
affected analysis incomplete. A separate budget of 100,000 attempts and 8 MiB
collects unused local identities when available; its exhaustion does not
consume the used-identity budget or load external files.

## Document deployment context

`parse_document` and `parse_with_loader` accept an optional `document_url`
(`Some(url)`). The CLI exposes it separately as `--before-document-url` and
`--after-document-url`. Each value must be an absolute HTTP(S) document URL,
without a fragment, within the 8,192-byte URI limit. Invalid explicit values
fail parsing even when the specification uses absolute authentication URLs.
Queries are allowed. No option implies the other side's address.

The source URI identifies input content, loader requests, cache entries, cycles,
and evidence locations. The document URL supplies deployment context for relative
servers. OpenAPI allows an expected retrieval location to differ from the current
physical location under its [base URI
rules](https://spec.openapis.org/oas/v3.1.1.html#relative-references-in-api-description-uris).
Providing a URL does not fetch it, enable file references, or change confinement.

With an explicit entry URL, each external document's URL is resolved from the
referring document URL and the original URI-escaped `$ref` file component.
The loader still receives a decoded relative file path. Encoded `#`, `?`, `%`,
and `/` retain their URI meaning during URL resolution. Nested references use
the current document's derived URL. Without an explicit entry URL, each HTTP(S)
source retains its existing default origin; local sources do not acquire a
guessed deployment address.

Two canonical sources can share an expected URL without merging content. One
canonical source with different derived URLs produces `ref.conflict`. Policies
whose relative server resolution depended on that ambiguous source are
withdrawn, including identities cached before the conflicting alias appeared.
Independent absolute-server or absolute-endpoint findings remain available.
The result is incomplete with exit code 2.

`Document.document_url` and `Comparison.before_document_url` /
`after_document_url` retain normalized entry context. JSON reports add
`document_urls: {before, after}`; SARIF records it in run properties. These
additive fields keep JSON `schema_version: 1`. Missing context is `null`.
Fatal load/parse reports contain `null` on both sides because no comparison was
constructed from parsed documents. Source locations continue to name the input
files and their JSON Pointers.

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
One entry's reference graph allows at most 64 documents, 64 MiB of encoded
text, and 1,000,000 parsed nodes. Extraction permits 10,000 operations and
250,000 expanded authentication atoms, including inherited requirements and
repeated referenced path items. These budgets apply before normalization;
exceeding them retains established findings and marks analysis incomplete.
The native CLI opens regular files, checks size on the open handle, and reads
at most 16 MiB plus one detection byte. File growth after the size check cannot
cause an unbounded read.

Only relevant path-item and security-scheme references are resolved. The default
parser accepts document-local JSON Pointers beginning with `#/`.
`parse_with_loader` additionally accepts relative file references, optionally
followed by a JSON Pointer. A missing or empty fragment selects the document
root. A fragment-only pointer belongs to the current referenced document.
Relative files resolve from that document's canonical source identity.
Security requirement names and global inheritance refer to the entry document,
following the OpenAPI guidance on
[implicit connections](https://spec.openapis.org/oas/v3.1.1.html#resolving-implicit-connections).
The loader returns parsed inputs through `SourceDocument`; requests and
canonical documents are cached, with conflicting source contents rejected.

Invalid pointers, cycles, conflicting referenced path-item definitions, and
unavailable relevant files are errors. Network, absolute, drive, backslash,
query-bearing, malformed-percent, and control-character file references are
rejected before invoking the loader. The native CLI confines local reads to
the selected directory, rejects links/reparse points, and checks the actual
opened file before a bounded read. Relative `..` is allowed only when the
resolved file stays within that boundary. External response schemas do not block the
authentication check because they are never traversed. No network requests are
made during analysis. Callback and webhook operations are not included.
Operation-object references are not part of OpenAPI's operation structure and
are rejected. OAuth scopes must be declared by at least one flow of the named
scheme. YAML directives must select version 1.2.

Locations carry the source URI and an RFC 6901 JSON Pointer. Syntax errors retain
available parser line and column information in diagnostics. Reports do not
fabricate line numbers for resolved nodes.

SARIF can render checkout-relative file locations and stable operation
fingerprints using a separate source-root configuration. Entry identities are
retained in `Comparison.before_source` / `after_source` and the reports'
`document_sources` object. These report features do not change policy extraction,
reference loading, or comparison results. See [SARIF in CI](sarif.md).
