# tokens

Internal module of `first-key`: a first key's mail tokens, and the answers of its mail's side.

## Responsibilities
- Issues a mail token for a subject and the code its start's screen shows, decides each request's try of it in one write of its record, and keeps the answer its mail's side was given.

## Not here
- Opening a request, its nonce, and naming its subject: the mail's side. Sending the mail: the start's job.

## Offers
- `tokensOf` (the build) → `tokensOver` over `firstKeyTokens`, `token-lifetime` and `code-tries`; `tokensTakes`, what it takes, which the path names among its takes.
- `codeOf` (random bytes) → a code of eight digits.
- `tokensOver` (the tokens' store, random bytes, the clock, the token's lifetime, the code's tries) → `issue` (subject, code, when its evidence began) → the token and its end; `attempt` (token, the request's nonce and digest, the subject the identifier names or none, the code) → `claimed` (with the token's own subject and when its evidence began), `used` or `refused`.
- Its answers: `keep` (the request, the token it claimed, E_sig and the statement); `answered` (the request) → the statement, only while its token is used by it; `recoverable` (nonce) → what a recovery is checked against, the digest and E_sig, never the statement.
- Its store, the package's: `firstKeyTokens` (`Kept`: create unless held, read, change from what it holds, never moving the lifetime), and its needs `firstKeyTokensNeeds`: never evicted, durable, replicated, confirmed reads, authenticated. The tokens and the answers name a subject.

## Invariants
- A token is 32 random bytes, base64url, kept by its SHA-256 under a key no caller sees; its code is kept only bound to it, never alone; it keeps its subject and when its evidence began.
- Each try is decided in one write of the token's record. An issued token whose subject and code a request names is claimed by that request, fixed to it. A request naming another subject, none, or another code is counted once, however often sent; at the code's tries the token is revoked, and every request is refused after.
- A claimed token is used by the request that claimed it alone; that request again finds it `claimed`, with the token's own subject whatever the identifier names now, or `used`; any other is refused, uncounted.
- An answer is given only while its token is used by its request, a token claimed by it marked used then: never to another request, never once the token ended.
- An answer is kept once for its nonce, the first answered to every call after, and lives a minute past its token's end, measured as it is written, so a late write moves its end on and never back. Its record names its token's key.
- A token holds until the end it was issued with, the store's lifetime aside: past it, or never issued, every try and use is refused. `issue` answers that end.

## Vocabulary
- request: a mail's side's sealed request, named by its nonce and its bytes' digest.
