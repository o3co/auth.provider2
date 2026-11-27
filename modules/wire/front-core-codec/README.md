# front-core-codec

## Responsibilities
- Encodes and decodes the frames of the Front to Core wire, as `front-core-wire`'s schema gives them, and reads and writes each operation's message as HTTP carries it, as its `overHttp` gives it: the one implementation the Front's relay and the Core's entrance both use, so the two read every field alike.

## Not here
- The wire's contract (the frame's form, the operations, their fields, the codes): `front-core-wire`.
- Reading what a field means: the Core's verifier of each. The connection and who may reach it, and reading or writing HTTP itself (bodies, headers, statuses): the http axis's adapters.

## Offers
- `encodeRequest` (kind, id, message) and `encodeReply` (reply): a frame, each field held to its spec, an enum's number and a text as given (never wrapped to a byte, never a lone surrogate sent as U+FFFD), bytes as bytes and a text as a string (an absent field empty, a value of another type refused); a field outside it throws `WireEncodeError`, naming the field and the code, for the honest side's own log.
- `decodeRequest` and `decodeReply` (bytes): a `Decoded` value, the frame's kind or outcome, its id and its fields, or the code it is rejected with and the id its header gave. They never throw.
- `readHeader` (bytes, the body's limit) and `frameSplitter` (the limit, `onFrame`, `onError`): a stream cut into whole frames.
- `checkField` (spec, bytes): the one check of a field's length and characters both sides run.
- `operationAt` (method, path, the body's values): the operation a request is, by the body value telling apart those sharing a path, or none. `messageOf` (kind, `Carried`: the body's values, the headers, the body's names of no text, and apart the source the Front determined) → the message, or the field it cannot carry and the code (`Read`); `carriedOf` (kind, message) → what the Core's route reads, the discriminator first, the declared source apart.
- A refusal, `Read`'s or a `WireEncodeError`, carries its OAuth `word` (`RefusalWord`), by one rule: the request object (`request`) sent once as a text not empty is `invalid_request_object` (RFC 9101 §6.2, §7); any other field, and it absent, empty, twice or of no text, `invalid_request` (RFC 6749 §3.1, §5.2).
- `requestOf` (kind, `Carried`) → `Read`: as `messageOf` reads it, every field then held to its spec as the encoder holds it, an enum's number and a text as read (a lone surrogate refused); what a Core's route reads before it acts on any field.
- `Message`, `WireRequest`, `WireReply`, `Decoded`, `Rejected`, `Header`, `FieldsOf` and `Value`: the values, typed from the schema.
- `./testing`: `fuzzer` (seed): well-formed frames of a kind and mutations of a frame, reproducible from the seed.

## Invariants
- A frame's id is written as its low 32 bits (`id >>> 0`), not refused: the caller keeps it within, as front-relay's ids are.
- A frame is read whole or rejected: a wrong version, kind or length, a truncated body or field, a field's length or characters outside its spec, an enum past its count and bytes after the last field each have their code; no piece of the input goes into a rejection.
- Only canonical frames are read: a frame read encodes back to the same bytes.
- A stream's splitter stops at the first header whose version or length is wrong, calling `onError` once and reading nothing after, before the body is waited for.
- A decoded field is a copy, so a buffer reused by the caller changes nothing read.
- Every message `carriedOf` writes, `messageOf` reads back the same. The declared source is read from `Carried`'s own member alone, never from the body or a header. It refuses a name sent twice, an enum text its `texts` lack where no `other` is, a number not in plain decimal, and bytes not in the one base64url text of them; a field's length and characters stay the encoder's to check.
- A wire field the body sent as no text (a name in `Carried`'s `mistyped`, which every reader of a body gives, empty where none) is refused, naming the field, never read as absent; any other name of no text is ignored, as an unknown text is.

## Depends on
- `front-core-wire` (the schema).
