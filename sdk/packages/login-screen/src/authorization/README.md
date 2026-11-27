# authorization

Internal module of `login-screen`: an authorization's steps on the screen.

## Responsibilities
- Reads T against the JAR the screen holds (or, under PAR, by the client and the `request_uri` the URL names), asks the passkey, takes the completion, signs the callback's proof; or ends the attempt with no code, by the person's denial or the Core's refusal carried.

## Offers
- `authorization`:
  - `read` (T, the JAR the screen holds, the ring, the screen keys, the issuer): T as a `ReadT` (the statement and its compact bytes), its items exactly what the JAR gives by sdk-core-wire's rule, or why not (`AuthorizationError`). Only `read` and `readPushed` make a `ReadT`; the next steps refuse any other.
  - `readPushed` (T, the client and the `request_uri` the URL names, the ring, the screen keys, the issuer): under PAR, where the screen holds no JAR, T as a `ReadT`, its client and `request_uri` the URL's, or why not (`PushedAuthorizationError`: a statement's refusal, `client` or `request_uri`). The JAR's hash is not checked, the screen holding no JAR; another request of the same client given at the URL is the relying party's to refuse by its state (R3).
  - `assertionOptions` (a `ReadT`, the RP id, the credentials if any): what a passkey's `get()` is asked: T's get challenge, user verification required; credentials given empty, or any one not a credential id, are refused; a T denied is `denied`.
  - `finish` (a `ReadT`, sealed, the completion's additional data, the screen keys, the ring, the issuer, the assertion's bytes, and the level the caller names, `FinishChecks`: `L0`, or `log` with ⑤'s receipt and the log's keys): at `L0` the code alone, no receipt checked (a bundle that fixes no log keys, as 0.1.0's); at `log` the code and ⑤'s record (shard, n); or why not (`FinishError`; a level not named is `checks`, a T denied `denied`). `Sealed`: an encapsulated key and a ciphertext.
  - `callbackProof` (a `ReadT`, the `Finished` that `finish` gave for it, the screen keys T names, the time): the callback's proof (A38) the screen adds to its POST to the RP, ES256 under E_sig, its header carrying E_sig's key; or why not, a `Finished` not given for this T among them, or one of `L0` (`level`: the proof names ⑤'s record, which only a receipt gives).
  - `denial` (a `ReadT`): what the page POSTs by `form_post` when the person refuses on the screen (RFC 6749 §4.1.2.1), a frozen `Denial`: `redirectUri` T's `redirect_uri`, and `fields` `error` `access_denied`, T's `state` and `iss` (RFC 9207; the issuer `readStatement` pinned), every value T's, none the URL's.
    - The T is then denied: `assertionOptions`, `finish`, `callbackProof` and `signUp`'s steps refuse it (`denied`), so a page brought back cannot approve or continue it. It revokes nothing sent already: an approval in flight is the Core's to judge until T's expiry.
    - It answers `statement` for a T not `read`'s or `readPushed`'s, `finished` for a T whose completion `finish` took (its code is the page's to POST), `ended` for a T the Core's refusal ended (`refusal`: its POST was made). Asked again, it answers the same.
    - No callback proof goes with it (there is no code); the relying party holds it to R3 (`state`), R4 (`iss`) and R12 (the POST's own checks), as a code's.
  - `refusal` (a `ReadT`, the `error` of the Core's refusal of the finish as the page read it): what the page POSTs for it by `form_post` (OIDC Core §3.1.2.6), a frozen `Refused` as a `Denial` is, `error` the Core's word: one of `access_denied`, `login_required`, `unauthorized_client`, `invalid_scope`, `invalid_target` (`CarriedRefusal`).
    - It ends T as `denial` does, one end per T: a `denial` after it is `ended`, it after a `denial` answers that denial. Any other word, the screen's own request's or the moment's or an unknown client's, is `refusal`, T not ended: the screen shows its own page.
    - The page asks it once it gives the attempt up: a refused approval the person may try again with another key is not yet its end.
    - The word is unauthenticated: a Front may make one up, even in place of a completion it holds, ending T with no code; the relying party fails the attempt on it and acts on it no further.
  - Where no T was read (② refused, or `read` or `readPushed` refused, a reload among them), the screen holds no `redirect_uri` it can trust: it shows its own error page and navigates nowhere. ⑤'s own refusals after T was read are `refusal`'s.

## Invariants
- At `L0` the Core's side of the login (claim 3's: A35's receipt and A38's proof) is not held: the completion is read alone, held to T, the assertion and its additional data.
- By value, the JAR is read without its signature, which the Core verifies, and the screen compares its items alone; under PAR the screen holds no JAR and compares the client and the `request_uri`.

## Depends on
- `sdk-core-wire`, `transparency-wire`.
- The package's `statement`, `completion`, `receipt`, `challenge`, `hpke`, `jws`, `keys` and `bytes`.
