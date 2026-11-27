# keys-kms

## Responsibilities
- Holds the keys of `keys`' rings in AWS KMS, where no one takes them out: signs with KMS's `Sign` and agrees with its `DeriveSharedSecret`, as the keys axis asks.

## Not here
- What the keys mean, which kid signs, and how a JWS or a sealing is made: `keys`.
- The key policies, the roles and the audit trail: the deployment's (below).

## Offers
- Composition definition only: the holder of the keys axis (`keyHolders`). It reaches KMS through `@aws-sdk/client-kms` (`network`: `kms`).
- The axis's default, as the strong side: a composition that names no adapter of the keys axis composes it; a development composition names `keys-local` instead.
- Operator section `keys-kms`: `region`, and `keys`, each a `kid` and the KMS key's `key-id`.
- `powers`: withdrawable outside the Core (by the key policy and IAM); its calls not counted outside the Core's account.
- `./testing`: `fakeKms`, a fake of the KMS calls it makes over the keys given (`FakeKey`, each failing as `serviceError` makes one), and `kmsServer`, those calls answered on KMS's wire on loopback, for the SDK's client to reach as the module does.

## Invariants
- Each key's public half is read once at boot (`GetPublicKey`); a key KMS does not have, one the Core may not read, and no answer refuse boot at the key's `key-id`.
- Every call after boot names the key ARN `GetPublicKey` answered, never the `key-id` as written, so an alias pointed elsewhere later changes no kid's key.
- It signs ES256 (`ECDSA_SHA_256`, the signature turned from DER into r and s), PS256 (`RSASSA_PSS_SHA_256`, its salt as long as the digest) and RS256 (`RSASSA_PKCS1_V1_5_SHA_256`), sending KMS the signing input's SHA-256 alone (`DIGEST`); a key of no such algorithm signs nothing. A P-256 key of `KEY_AGREEMENT` with ECDH agrees.
- KMS denying the Core (`AccessDeniedException`) or the key disabled or not usable (`DisabledException`, `KMSInvalidStateException`) is `withdrawn`; no answer, the service's fault or throttling is kernel's `Unavailable`; any other refusal is thrown as it is, and so is an answer with no signature or secret, or a signature that is no DER: never an empty success.
- It declares no stance: a key no one takes out is what `core-compromise-contained` rests on, not enough for it to hold.
- It ends its client at stop, and holds only public halves, so it is safe on many instances.

## Deployment
- KMS in `region`, reached from the Core's network; its credentials the Core's role, by the SDK's default chain. The Front's role holds no KMS permission.
- Held by Node's permission model (`enforce`), the chain's providers taken are the environment's credentials, the instance's role, web identity by `AWS_WEB_IDENTITY_TOKEN_FILE`, container credentials by `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, and the shared files by `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` (`~/.aws/*` where unset; a `~/` in either the home directory, as the SDK reads it), as its `permissions` declare.
- Not taken under `enforce`: a profile's own `web_identity_token_file`, `credential_process` (it starts a program), and SSO or login caches.
- Where the SDK sends its calls: the region's KMS endpoint, unless `AWS_ENDPOINT_URL_KMS`, `AWS_ENDPOINT_URL` or a shared config's `endpoint_url` names another. Whoever sets them chooses where the signing goes, plain http included.
- The authority's keys and the Core's ring: `SIGN_VERIFY`, `ECC_NIST_P256` (ES256) or an RSA spec of 2048 bits or more (PS256 or RS256). The sealing key: `KEY_AGREEMENT`, `ECC_NIST_P256`.
- The Core's role: `kms:GetPublicKey` on every key named; `kms:Sign` only on the authority's signing key and the Core generation's own key; `kms:DeriveSharedSecret` only on the sealing key. A next key and a later generation's key carry no `kms:Sign` until it is to sign.
- A key administrator apart from the Core's role holds `kms:PutKeyPolicy`, `kms:DisableKey` and `kms:EnableKey` and no `kms:Sign`; disabling a key or removing a grant is how signing is withdrawn.
- The publisher's key is in another account with another owner, never one of these.

## Depends on
- `kernel`, `keys`, `zod`, `@aws-sdk/client-kms`.
