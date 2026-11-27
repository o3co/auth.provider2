# screen

Internal module of `interop-oidf`: the login screen as the suite's browser meets it, for its tests alone.

## Responsibilities
- Plays the login screen on the real SDK (`@sdk/login-screen`) with webauthn's software authenticator, server-side: a login under PAR by the client and `request_uri` alone, approved by the person's passkey or denied, and a sign-up making that passkey.
- Serves its pages at the screen's origin behind an https front (`conformance-front`): the authorization page with two buttons, `approve` and `deny`; a refused start sent to a page of its own, `/refused`; the answer to the RP's redirect URI by `form_post`, or by a query where the run says so.
- Keeps what each start was answered, by its URL's `request_uri` and `state`: taken, or refused (at the start, or after T: the approval, or a decision that does not go through), with who refused (the provider, in its words; the SDK, the browser or the page, in theirs).

## Not here
- The provider: `scene`. The relying party: `rp`. The suite's browser and what it presses: the suite's configuration.
- Keeping the suite's own review pages: the run's.

## Offers
- `loginScreen` (the pins, read at each step; a browser; the RP's name) → `startPushed`, `signUp`, `approve`, `deny`, `carry`; `stopped`, `Stopped`, `Callback`, `Denied`, `Refused`, `Started`, `Pins`, `Post`.
- `startPages` (the host and the address to listen on, a directory, the screen, how it reaches the issuer, how the answer is carried, read for each answer) → `Pages`: their origin, the certificate their front answers with, what they saw, their stop.
- `browser` (an origin) → `Browser`: `navigator.credentials` over a software authenticator; `attestedKey`.
- `signedIn` (a client id, a redirect URI) → `SignedIn`: a scene, its pages and an RP registered, a person signed up; a login through the screen role to the RP's tokens; the stop of all of it. What a later step's tests (the resource's, the run's) start from.

## Invariants
- The screen's steps are the SDK's own, unchanged: T read against the client and the `request_uri` the URL names, the completion opened at L0 (the callback's proof is not made: A35, A38 are outside), the denial built by the SDK.
- Each start is under new screen keys, the URL's `client_id` and `request_uri` sent as they came, absent where absent, for the provider to answer. T is kept until its page's decision, or ten minutes undecided (past T's own life).
- Only the `approve` button approves; a decision naming neither, or no start open, goes to `/refused`.
- The Core's refusal of the finish is carried to the RP as a denial is (the SDK's `authorization.refusal`: its word, T's state and issuer; OIDC Core §3.1.2.6) and kept `carried`; any word the SDK does not carry ends on `/refused`.
- A passkey made by the software authenticator stands for no check of a real browser's origin rules, WebAuthn's UI, or what consent shows.
- Taken from attack-harness's roles (the screen's steps and the browser), which G14 lets no package share: the plan's interim, until the SDK offers a screen for tests, which both harnesses then take.
- Its files are tests' (`test/`), typed by the root's `tsconfig.sdk-tests.json` (the DOM's types the SDK reads), as every test file of the package is: any of them may reach the SDK through it.

## Depends on
- `@sdk/login-screen`, `sdk-core-wire` (`hpke`), `webauthn` (`./testing`'s software authenticator), `conformance-front`; its tests: `scene`, `rp`, `lifecycle` (`stopAll`).
