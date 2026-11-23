# discovery

## Responsibilities
- Builds the discovery document from `issuer`'s URL and metadata items, and writes it to files for the publisher to serve.

## Not here
- The metadata extension point and its rules: `issuer`.
- What each item means and holds: the contributing side's.
- Serving the files: the publisher, which answers each place with or without a trailing `/`, as JSON, to the pages it lets read them.

## Offers
- `discovery`: `publish`, the app entry `discovery-publish <directory>`, writing the document at OpenID Connect Discovery's place (the issuer's path, then `.well-known/openid-configuration`) and at RFC 8414's (`.well-known/oauth-authorization-server`, then the issuer's path), each a path under the directory; `Published`, the lines it writes and its exit code.

## Invariants
- Only what is upheld is published: an item of a feature not composed is absent, and an item without a value, or whose value is a list with no elements, is left out.
- A member whose omission means a default is never empty: its contributor publishes it or refuses boot.
- `issuer` is `issuer`'s URL, and comes first.
- The document is fixed at boot, so each run writes the same bytes: one JSON object and a newline.
- For an issuer without a path both places are at the directory's root; for one with a path, nothing is written at the root, as a document there would name another issuer.
- A place's path is the issuer URL's, its dot segments resolved and the rest as the URL encodes it, so no place leaves the directory.
- Each file is written beside its name and renamed, so a reader never sees half a document. Given other than one directory, it writes nothing and answers a usage line and 64.

## Data
- The document, built once at boot.

## Depends on
- `kernel`, `issuer`

## Vocabulary
- discovery document: `issuer`'s metadata items as one JSON object, `issuer` first.
- place: where a client looks for the document, a path under the issuer's origin, and under the directory as written.
