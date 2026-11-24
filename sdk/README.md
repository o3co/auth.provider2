# sdk

The receivers' parts: a workspace apart from the provider's, released with it under one version number.

| package | what |
|---|---|
| login-screen | the login screen's SDK |
| rp-kit | the relying party's checks |
| guard | the check that the packages depend on the provider's protocol packages alone (tooling, not released) |

## Working here
- Install the provider's workspace first (the protocol packages resolve their own dependencies there), then this one: `pnpm install` at the repository's root, then `pnpm install` here.
- `pnpm check` here runs the typecheck (the packages' shipped code against the web's standard APIs alone, no Node types; tests and tools against Node's), the tests and the guard. The repository's lint covers these files too.

## Dependencies
- A package depends on the provider's protocol packages alone, never on another package here: code both need is each one's own.
- No third party's package: `zod` reaches a bundle only as the protocol packages' peer.
- The pnpm pin and the supply settings are the provider's (the guard's S3).

## What changes at release
- Each `link:` to a protocol package becomes that package's released version, the same number as the provider's and the sdk's; the protocol packages' peer `zod` becomes a peer here too, and the guard's S1 takes it.
- `private` goes, and each `exports` names built files instead of the TypeScript sources.
- A release is checked by installing its packed tarballs alone, outside both workspaces.
