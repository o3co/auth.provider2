# registry-sign

## Responsibilities
- The publisher's tool: signs one version of the client registry, as the publisher hands it to a Core, outside the provider's process and trust domain.

## Not here
- What a version holds and its type: `registry-wire`. Reading a signed version and trusting it: the Core's registry source (`clients-registry`).
- Keeping the publisher's private key, numbering the versions and delivering them: the publisher's.

## Offers
- `registry-sign <private-key.jwk> <version.json> <out.jws>`: reads a private JWK and a version as JSON, and writes the compact JWS of the version, with a newline.
- The header is `alg`, `typ` (`registryWire.typ`) and `kid` (the key's); the payload is the version as `registryWire.version` read it.
- The private JWK is the publisher's to make and keep: Node's `generateKeyPairSync("ed25519")` (or `"ec"` on P-256), its private key exported as `{ format: "jwk" }` with a `kid` and its `alg` (`EdDSA`, or `ES256`) added. Its public half, without `d`, is the Core's `clients-registry.publisher-key`.
- It writes one line: on success to standard output, `signed version <n> (<count> clients) as <kid> under <alg>`, exit code 0; on a refusal to standard error, what is wrong, exit code 1; wrong arguments, its usage, exit code 64.

## Invariants
- The key is a private JWK with a non-empty `kid`: Ed25519 signs under `EdDSA`, P-256 under `ES256`; a key of another kind, or whose own `alg` names another, is refused.
- A version that does not fit `registryWire.version` is refused, naming where it fails.
- The signature is checked under the public half the JWK names before anything is written; one that does not verify is refused.
- An output that is the key file or the version file, by a link too, is refused.
- A refusal writes no file, and no line names a private member's value.
- It depends on the protocol alone: no other part of the provider runs in it.

## Depends on
- `registry-wire` (the version and its `typ`); `zod`, which registry-wire takes as a peer (src imports none of it); Node's built-ins.

## Vocabulary
- version: one signed state of the client registry, as `registry-wire` names it.
