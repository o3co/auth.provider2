# Deviations gather: report (cloud worker)

These are candidate rows gathered from the design spec (auth.provider2.spec, `main`) for the L1 ledger, `docs/compliance/deviations.json`. Review them before the page is published. Line numbers refer to `docs/proposal.md` in the spec repository as of this gather. The standards were read from their official sources: openid.net (OIDC Core 1.0 with errata set 2, OIDC Discovery 1.0, FAPI 2.0 Security Profile final), w3.org (WebAuthn Level 3) and rfc-editor.org.

The 15 rows already in the ledger were not changed. This gather adds 7.

## New rows

| Key | Kind | Spec location | Standard checked |
|---|---|---|---|
| `id-token-rs256-unsupported` | deviation | F4 (l. 1601); §5.1 settings, `keys.signing.alg`, `oidc.id-token-alg` (l. 1133); Q42 (l. 1519, Config OP and RS256) | OIDC Core §15.1 ("OPs MUST support signing ID Tokens with the RSA SHA-256 algorithm ... unless the OP only supports returning ID Tokens from the Token Endpoint ... and only allows Clients to register specifying none"); OIDC Discovery §3 `id_token_signing_alg_values_supported` ("The algorithm RS256 MUST be included"); FAPI 2.0 SP §5.4.1 (PS256, ES256, EdDSA). The Core exception does not apply, because clients register ES256, not `none` |
| `rs256-not-accepted` | strict | F4 (l. 1601); §5.1 settings (l. 1133: "`dpop.algorithms` と `client-assertion.algorithms` の既定も RS256 を含むので、nextgen の構成で絞る") | OIDC Discovery §3 `token_endpoint_auth_signing_alg_values_supported` ("Servers SHOULD support RS256") and `request_object_signing_alg_values_supported` ("Servers SHOULD support none and RS256"); FAPI 2.0 SP §5.4.1 |
| `userinfo-not-offered` | strict | G1 (l. 1602); §3.11 table, the introspection and userinfo row (l. 460); §5.1 settings (l. 1140); L1's list (l. 1610) | OIDC Discovery §3 `userinfo_endpoint` ("RECOMMENDED"); OIDC Core §5.4 (the claims of the `profile`, `email`, `address` and `phone` scopes "are returned from the UserInfo Endpoint ... when a response_type value is used that results in an Access Token being issued"). This sentence has no RFC 2119 keyword, so the row is strict, not a deviation |
| `client-keys-written-only` | strict | R8 (l. 112); §3.11 (l. 469); §0.2, the 2026-11-26 split (registry records do not fetch `jwks-uri`); L1's list (l. 1610) | RFC 7591 §2 `jwks_uri` ("Use of this parameter is preferred over the "jwks" parameter, as it allows for easier key rotation") |
| `webauthn-uv-required` | strict | C2 (l. 93: "UV を必須にし"); §3.4 step ④ (l. 282); §3.5 (l. 328); §5.1 settings (l. 1138) | WebAuthn L3 §5.5 (`userVerification` "defaulting to "preferred""); §5.8.6 (`preferred`: "will not fail the operation if the response does not have the UV flag set"); §7.2 (check the UV bit only when user verification is required) |
| `webauthn-rs256-not-offered` | strict | V22 (1) (l. 1655); §3.13 passkey key form (l. 580: `webauthn.algorithms` default `["ES256", "EdDSA"]`) | WebAuthn L3 §5.4 `pubKeyCredParams` ("Relying Parties that wish to support a wide range of authenticators SHOULD include at least ... -8 (EdDSA) -7 (ES256) -257 (RS256)") |
| `cc-dpop-client-key` | strict | V21 (4) (l. 1654); §3.3, the DPoP rule for client_credentials (l. 251); §3.11 "束縛" (l. 476) | RFC 9449 §11.11 (DPoP "is only bound to authentication by being coincident in the same TLS tunnel"; a stronger binding "is beyond the scope of this specification") |

The rows' behaviour was checked against the implementation's module cards on `develop`: `oidc`, `keys`, `client-assertion` and its internal `keys`, `userinfo`, `passkeys`, `webauthn`, `client-credentials`.

Notes for review:
- `id-token-rs256-unsupported` and `rs256-not-accepted` describe nextgen's configuration (F4, ES256). The implementation lets an operator configure RS256 with a warning, so they could be read as configuration rows, as `jar-required` is.
- `userinfo-not-offered` also states that introspection is off. Introspection has no row of its own, because no standard expects it (see "not a deviation").
- `cc-dpop-client-key` applies only where client_credentials is composed, which is opt-in and a weakening choice (V21).

## Unconfirmed

- **Errors before T shown on the screen, with no redirect** (A20, the 2026-11-27 owner decision in §3.3, l. 255: "そのとき画面は誤りを自分の page に出し、どこにも移らない"). This applies to a reload or a second tab whose E keys differ. RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 say that for errors other than a bad redirect URI the AS "informs the client" at the redirect URI. Neither uses an RFC 2119 keyword, so the row's kind (deviation or strict) is not settled. Under PAR, Core holds a redirect URI it has already checked, but the screen does not. The owner should decide whether this is a row, and of which kind.
- **Bounds on RS256 passkey keys** (V22 (1), l. 580: n of 2048 to 4096 bits, e = 65537 only). WebAuthn L3 sets no RSA bounds. RFC 8230, which sets the COSE RSA key rules, was not fetched for this gather, so whether the 4096-bit cap and the fixed exponent are stricter than the standard is not confirmed.

## No decision ID

- **DPoP server nonce required at the token endpoint** (§5.1 settings, l. 1150: `dpop.nonce.required` default `as`; `never` is a weakening choice). RFC 9449 §8 says "An authorization server MAY supply a nonce", and FAPI 2.0 SP §5.3.2.1 says "may use the server provided nonce mechanism". Requiring the nonce is the strict side of what both allow. The spec gives this setting no decision ID.
- **`private_key_jwt` `aud` must be the issuer as one string** (§3.3, l. 254). OIDC Core §9 says "The Audience SHOULD be the URL of the Authorization Server's Token Endpoint". The implementation refuses that URL, or an array, unless `accept-loose-audience` is set. FAPI 2.0 SP §5.3.2.1 requires this choice ("shall only accept its issuer identifier value ... as a string in the aud claim"), so a row may not be needed at all. If one is wanted, it is strict relative to OIDC Core, but the spec line has no ID.

## Not a deviation

- PAR only, with no request by value, in the FAPI configuration (F4, §3.3): FAPI 2.0 SP §5.3.2.2 requires it ("shall reject authorization requests sent without [RFC9126]").
- `response_type` `code` only (§3.3): FAPI 2.0 SP §5.3.2.2 ("shall require the value of response_type ... to be code"). OIDC Core §15.2 asks for more response types only of Dynamic OPs.
- Authorization code lifetime of 60 s or less (§5.1 settings, l. 1139): FAPI 2.0 SP §5.3.2.1 requires it.
- Refresh tokens are not rotated (Q42): FAPI 2.0 SP §5.3.2.1 ("shall not use refresh token rotation except in extraordinary circumstances").
- No ID token in the refresh response (Q42, `oidc` card): OIDC Core §12.2 ("it might not contain an id_token").
- No `client_secret` and no mTLS client authentication or binding (D3, §3.3): FAPI 2.0 SP §5.3.2.1 lets the AS use one of MTLS and DPoP, and one of MTLS and `private_key_jwt`. RFC 6749 §2.3.1's Basic MUST applies only to clients issued a password, and nextgen issues none.
- Grants limited to authorization code and refresh (C7, §3.11): no standard requires other grants. FAPI 2.0 SP Note 2 leaves the grant set open.
- Introspection not offered (G1): RFC 7662 is optional, and neither FAPI 2.0 nor OIDC requires it. UserInfo is the row above.
- No RP-initiated logout or `end_session_endpoint` (O12, R14): RP-Initiated Logout is an optional specification.
- No SSO without a tap (C6, D6): OIDC Core lets an OP authenticate the person every time. `prompt=none` is already the row `prompt-none-at-par`.
- `c_hash` always in the ID token (A21): OIDC Core allows the claim in the code flow, so including it fails no test. Requiring the RP to check it (R15) is an RP duty.
- RP and RS duties R1 to R18 (§0.1): these bind receivers and the SDK nextgen ships, not the provider a conformance run tests. R1 (no TLS-based substitute for checking the ID token signature, against OIDC Core §3.1.3.7) would be a candidate for a separate RP-side ledger.
- Typing JWTs by `typ` (`dpop+jwt`, `client-authentication+jwt`, §3.3): RFC 9449 already requires `dpop+jwt`, and the implementation does not require a `typ` on client assertions.
- Empty `webauthn.top-origins` and refusing `crossOrigin` (§3.4 step ⑤, §5.1): WebAuthn L3 §7.2 leaves it to the Relying Party whether it expects use in a cross-origin iframe. Refusing one it does not expect is the standard behaviour.
- Attestation `none` (§3.4): this is WebAuthn L3's default conveyance.
- Short access token, T and client_credentials lifetimes (J1, §3.11, §5.1): no standard sets these lifetimes.
- T's length bound (V28 (2)): no standard sets or forbids a size limit on the request. The part a test sees, the lengths of `state` and `nonce`, is already the row `state-nonce-bound`.
- JAR `exp` and `nbf` required: FAPI 2.0 Message Signing §5.3.1 requires them, as the spec's `docs/deviations.md` says of `nbf` and the row `par-jar-lifetime` cites. Message Signing was not read again for this gather.
- The same JAR pushed twice to PAR shares one reservation (A20, §3.3): the client sees this as `request-uri-once` and `jar-jti-required`.
- client_credentials requires a named scope and at most one `resource` (V21): the grant is opt-in. RFC 6749 §3.3 lets the AS "fail the request indicating an invalid scope" when the client omits `scope`.
- An `openid` client requires an authority ring of a SHA-256 algorithm (V24, A21): this is an internal constraint on configuration, not a protocol choice a client sees.
