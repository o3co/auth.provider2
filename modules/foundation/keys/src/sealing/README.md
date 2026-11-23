# sealing

Internal module of `keys`: HPKE (RFC 9180, base mode), in the suite sdk-core-wire names.

## Responsibilities
- Seals to a screen's key (the completion's answer, the first key's code) and a preimage to a monitor's key, and opens what a screen sealed to the Core's sealing key (the first key's requests).

## Not here
- What is sealed, its additional data, and the words of the suite and of each sealing's info: the caller's, sdk-core-wire's `hpke` and transparency-wire's `sealing`.
- The Core's private key: the holder agrees the Diffie-Hellman secret with it, and nothing else of it is read.

## Offers
- `sealing` (the holder, the sealing key, the randomness, the log → `keys`' `seal` and `open`), and, of HPKE itself, `sealTo`, `openWith`, `derivedKeyPair` and `onCurve`.

## Invariants
- The suite is chosen by sdk-core-wire's words, from the suites implemented here: `DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-128-GCM`.
- It opens only under an info sdk-core-wire names, and seals under those and transparency-wire's preimage info where that suite is this one; another is the caller's TypeError. It opens no preimage: the Core holds no monitor's key.
- Each sealing is under a fresh sender key, derived (DeriveKeyPair) from 32 bytes of the kernel's randomness; a recipient key that is no P-256 point is the caller's TypeError.
- What does not open (another key, info or additional data, bytes changed, a sender key off the curve) is `unopened`; the holder's `withdrawn` passes on as it is.
- RFC 9180's test vectors for the suite are met.

## Depends on
- None (`keys`' contract)
