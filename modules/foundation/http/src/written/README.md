# written

Internal module of `http`: a JSON answer as a server writes it, held to the rule that the provider writes no member as null.

## Responsibilities
- Writes a JSON answer's value as JSON, and reads the text back for the nulls inside it (OpenID Connect Core §13.3: a member with no value is left out, never null).

## Not here
- Writing the answer and what a server does with one holding a null (its status, its log line): each server's.
- A claim's nulls in what `keys` signs: `keys`' own rule, the same walk for another value.

## Offers
- `writtenJson` (a JSON value) → `WrittenJson`: its text, or the paths of the nulls inside it, on `http`'s `./server`.

## Invariants
- A null inside the text is found at any depth, as an object's member (`a.b`) or an array's element (`a[1]`, a top-level list's `[1]`), its path naming members as they are named; a path never carries a value.
- What JSON writes is what is read: NaN, Infinity, undefined in a list and a toJSON giving null are nulls; each toJSON is called once.
- A top-level null holds no null inside it and is left as written, as is a value JSON writes as nothing (no text).
- A value JSON cannot write (a cycle, a BigInt, a toJSON that throws) throws as JSON throws; the server answers it as any failure.

## Depends on
- Nothing.
