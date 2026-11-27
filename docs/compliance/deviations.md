# Intended deviations and strict choices (L1)

<!-- Written from deviations.json by `pnpm --filter @mod/interop-oidf run deviations`; edit the ledger, never this page. -->

The provider runs the OpenID Foundation's conformance tests on its strongest configuration and publishes, for each test that fails, why it is deliberately strict, in terms of the threat model (L1). This is the list those explanations are written from. A conformance run's expected failures name a row by its key: a failure no expected entry explains fails the run, and so do an expected entry naming no row and an expected entry no test used. A row no run uses is kept: the list is of the provider's choices, not of one plan's.

Gathering every other choice the design names is an L1 item for the gate. The rows below are the ones written so far.

Two kinds of row:
- **deviation**: the standard's normative text (MUST, MUST NOT) is not followed.
- **strict**: the standard allows it, but nextgen takes the strict side, so a test expecting the permissive side fails.

| Key | Kind | Standard | Its text | nextgen | Why | Decision |
|---|---|---|---|---|---|---|
| `par-dpop-header-only` | deviation | RFC 9449 §10.1, taken in by FAPI 2.0 §5.3.2.1 item 12 | An AS accepts the DPoP key from the PAR request's DPoP header alone | `dpop_jkt` is required in the signed JAR. A DPoP header on PAR must match it; a header alone is refused | With the header alone, a compromised Front reposts the RP's JAR with its own key's header, binds T to the attacker's key, and gets both the victim's token and the key it is bound to (Tamarin `PAR_DPOP_HEADER_ONLY`) | A44 |
| `claims-null-nested` | deviation | OIDC Core §5.5 | Members of a claims request that are not understood MUST be ignored | The direct members of `id_token` and `userinfo` written as null are read as `{}` (the same meaning). Any other null in `claims` is refused at /login/start with 400 `invalid_request_object` | The statement T the person approves is signed whole, and the signer writes no null (OIDC Core §13.3). A part of the request that cannot be signed as given is refused before the person is asked, never silently dropped from what they approve | V26 |
| `jar-dpop-jkt-required` | strict | RFC 9449 §10; FAPI 2.0 §5.3.3.1 Note 2 | `dpop_jkt` is an optional authorization request parameter; FAPI does not require the client to send it | A JAR without `dpop_jkt` is refused | When the Front relays the token request, binding the authorization to the RP's DPoP key in the signed request is what keeps a compromised Front from redeeming the code under its own key (claim 1) | L1, C2 |
| `refresh-dpop-bound` | strict | RFC 9449 §5; FAPI 2.0 §6.1 | A confidential client's refresh token need not be bound to the DPoP key; FAPI names rotating the key without losing the grant as a benefit | A confidential client's refresh family is bound to the authorization's DPoP key; a refresh under another key is refused | A family not bound to the key can be refreshed by whoever holds the token, including a compromised Front that saw it (claim 2) | L1, Q27 |
| `rar-refused` | strict | RFC 9396; FAPI 2.0 (RAR allowed) | An AS may accept `authorization_details` | `authorization_details` is refused at PAR and on every grant at the token endpoint | Per-operation authorization belongs to the RS and 4s-intent, not the IdP (V6); accepting it would make the IdP decide operations | A25 |
| `jar-required` | strict | FAPI 2.0 Security Profile; RFC 9101 | The Security Profile accepts an authorization request without a signed request object | Every authorization request is a signed JAR (PAR in a FAPI configuration, F4) | Without a signed request, a compromised Front rewrites the request the person approves (claim 1's code-grant hole). Applies only if the Security Profile plan is run | F4, 0.8 |
