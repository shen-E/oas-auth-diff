# Changelog

## 0.14.0

- Resolve Path Item and parameter chains before checking duplicate parameters,
  path-template coverage, operation identities and security scheme names.
  Preserve operation overrides and actual target locations.
- Bound cross-object checks to 250000 visits; leave ambiguous Path Item
  reference siblings incomplete.
- Report the current tool version in authorization, compatibility and validation
  SARIF instead of retaining an older release identifier.
- Add an independent library consumer and manual workflows for registry
  installation on three platforms and GitHub SARIF uploads.
- Document a reproducible walkthrough of the document and semantic commands.
