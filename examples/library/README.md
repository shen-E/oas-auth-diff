# Use the portable libraries

This independent module imports the published release. From this directory:

```sh
moon test --target all
```

The examples cover permission witnesses, Schema inclusion, static anchors,
authorization reports, client compatibility and offline specification validation.
They do not read files or make network requests. Only dependency installation
uses the registry.

To test a local checkout, copy this directory beside the module checkout and run
`moon work init library oas-auth-diff` from their parent. Run the same tests
from the workspace. The registry workflow instead copies these files into an
isolated temporary directory and downloads the release.
