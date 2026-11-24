# rp-kit

## Responsibilities
- The relying party's kit: the checks an RP runs on what the provider hands it.

## Not here
- The callback's proof (its `typ` and fields), the ID token's `esig` and `apr` claims, and the inputs of the RP's, the RS's and the screen's receipt checks: they wait for the protocol's review.
- The login screen's side: `login-screen`.

## Offers
- Nothing yet.

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard).

## Depends on
- `sdk-core-wire`, `transparency-wire`.
