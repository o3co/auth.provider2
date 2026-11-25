# text

Internal module of `transparency-wire`: the one JSON reading, the canonical spelling, and the base64url, UTF-8 and P-256 readings the other internal modules build on.

## Responsibilities
- Reads a JSON text the one way every reader of this wire does, and spells a value as canonical JSON, so both sides build the same bytes.
- Reads bytes from their base64url spelling, text from strict UTF-8, and a P-256 point from its coordinates.

## Not here
- What a token's digest covers, `esig`'s input and the receivers' checks: `receipt-gate`, which reads by these. The words: `words`. The schemas: `records` and the modules built on it.

## Offers
- `readJson` (text) → the value, or why it is refused (`not_json`, `duplicate_key:<key>`, `number`): what `tokens.parse` gives.
- `canonical` (value): object keys sorted, undefined members left out.
- `bytesOf` (base64url) → bytes; `textOf` (bytes) → text; `coordinate` (43 base64url characters) → a 32-byte value; `onP256` (x, y).
- `isObject`; `unique` (list, key): whether no two items share a key.

## Invariants
- `readJson` refuses a text that is not JSON, a key named twice in one object at any depth (keys compared as decoded, escapes and all), and a number past a double.
- `bytesOf` takes bytes' one unpadded base64url spelling alone; `coordinate`, 43 base64url characters, the last one's two spare bits zero; `textOf`, strict UTF-8 alone (shortest forms, no surrogates). Each gives none for any other.
- A point is P-256's where each coordinate is below the field prime and y² = x³ − 3x + b.

## Depends on
- Nothing, not even `zod`.
