# written

Internal module of `http`: a JSON answer as a server writes it, held to the rule that the provider writes no member as null.

## Responsibilities
- Writes a JSON answer's value as JSON writes it, and reads the text back for the nulls inside it (OpenID Connect Core §13.3: a member with no value is left out, never null).

## Not here
- Writing the answer and what a server does with one holding a null (its status, its log line): each server's.
- A claim's nulls in what `keys` signs: `keys`' own rule, the same walk for another value.

## Offers
- `writtenJson` (a JSON value) → `WrittenJson`: its text, or the paths of the nulls inside it, on `http`'s `./server`.

## Invariants
- A null inside the text is found at any depth, as an object's member (`a.b`) or an array's element (`a[1]`, a top-level list's `[1]`), its path naming members as they are named; a path never carries a value.
- What JSON writes is what is written, byte for byte, its toJSONs, getters and a proxy's traps called in JSON's order, and what is read back: NaN, Infinity, undefined in a list, a raw null and a toJSON giving null are nulls; each toJSON is called once.
- Written by a stack of its own, never the engine's (Node 24's JSON.stringify overflows where JSON.parse reads on): a value is written whole to 100,000 open objects or lists deep on every engine served.
- Deeper is refused: the write throws a RangeError, the engine's own class, which a server answers as any failure (500, the class logged). Why: a toJSON in server code opening a new object without end would take the process's memory; request data cannot (JSON.parse gives no functions).
- A top-level null holds no null inside it and is left as written, as is a value JSON writes as nothing (no text).
- A value JSON cannot write (a cycle, a BigInt, a toJSON that throws) throws what JSON throws, the same error class; the server answers it as any failure.

## Depends on
- Nothing.
