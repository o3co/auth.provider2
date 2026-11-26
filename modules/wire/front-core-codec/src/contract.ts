import {
	type FieldSpec,
	type FieldType,
	headerLength,
	maxReplyBody,
	maxRequestBody,
	type Outcome,
	type OverHttp,
	outcomes,
	overHttp,
	type RequestKind,
	replies,
	requests,
	version,
	type WireErrorName,
} from "@mod/front-core-wire";

/** A field's value as read: bytes, an enum's number, or text. */
export type Value<T extends FieldType> = T extends "bytes"
	? Uint8Array
	: T extends "enum"
		? number
		: string;
/** The values of a list of fields, by their names. */
export type FieldsOf<F extends readonly FieldSpec[]> = {
	[S in F[number] as S["name"]]: Value<S["type"]>;
};

/** What a request of one kind carries, field by field, as its schema types it. */
export type Message<K extends RequestKind> = FieldsOf<(typeof requests)[K]["fields"]>;
export type WireRequest = {
	[K in RequestKind]: { kind: K; id: number; message: Message<K> };
}[RequestKind];
export type WireReply = {
	[O in Outcome]: { outcome: O; id: number; message: FieldsOf<(typeof replies)[O]> };
}[Outcome];

/** A frame rejected: the code, and the id its header gave (0 where none was read). */
export type Rejected = { readonly ok: false; readonly error: WireErrorName; readonly id: number };

/** A frame read, or rejected. */
export type Decoded<T> = { readonly ok: true; readonly value: T } | Rejected;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

const isBase64url = (c: number) =>
	(c >= 0x41 && c <= 0x5a) ||
	(c >= 0x61 && c <= 0x7a) ||
	(c >= 0x30 && c <= 0x39) ||
	c === 0x2d ||
	c === 0x5f;

function syntaxError(
	type: FieldType,
	bytes: Uint8Array,
	values?: number,
): WireErrorName | undefined {
	switch (type) {
		case "bytes":
			return undefined;
		case "enum":
			return values !== undefined && (bytes[0] ?? 0) < values ? undefined : "enumRange";
		case "visible":
			return bytes.every((c) => c >= 0x21 && c <= 0x7e) ? undefined : "fieldSyntax";
		case "b64url":
			return bytes.every(isBase64url) ? undefined : "fieldSyntax";
		case "jws": {
			let dots = 0;
			let segment = 0;
			for (const c of bytes) {
				if (c === 0x2e) {
					if (segment === 0) return "fieldSyntax";
					dots++;
					segment = 0;
				} else if (isBase64url(c)) segment++;
				else return "fieldSyntax";
			}
			return dots === 2 && segment > 0 ? undefined : "fieldSyntax";
		}
		case "utf8":
			try {
				utf8.decode(bytes);
			} catch {
				return "fieldSyntax";
			}
			return bytes.every((c) => c >= 0x20 && c !== 0x7f) ? undefined : "fieldSyntax";
	}
}

/** One field's bytes against its spec: the length first; an empty field, where its least length lets it be, is not read further. */
export function checkField(spec: FieldSpec, bytes: Uint8Array): WireErrorName | undefined {
	if (bytes.length < spec.min || bytes.length > spec.max) return "fieldLength";
	return bytes.length === 0 ? undefined : syntaxError(spec.type, bytes, spec.values);
}

/** An honest side's refusal to encode: the field and the code, for its own log alone. */
export class WireEncodeError extends Error {
	readonly field: string;
	readonly code: WireErrorName;
	constructor(field: string, code: WireErrorName) {
		super(`wire: ${field} ${code}`);
		this.field = field;
		this.code = code;
	}
}

/**
 * A value held to its spec as given, before its bytes could change it: an enum's number to its
 * count, never wrapped to its one byte; a text whole, a lone surrogate never sent as U+FFFD; bytes
 * as bytes and a text as a string, a value of another type never sent as an empty one.
 */
function givenError(spec: FieldSpec, value: unknown): WireErrorName | undefined {
	if (spec.type === "enum") {
		const n = value ?? 0;
		return Number.isInteger(n) && (n as number) >= 0 && (n as number) < (spec.values ?? 0)
			? undefined
			: "enumRange";
	}
	// Absent, a field is empty, as before; given, it is of its type, never read as an empty one.
	if (value === undefined || value === null) return undefined;
	if (spec.type === "bytes") return value instanceof Uint8Array ? undefined : "fieldSyntax";
	return typeof value === "string" && value.isWellFormed() ? undefined : "fieldSyntax";
}

function bytesOf(spec: FieldSpec, value: unknown): Uint8Array {
	if (spec.type === "enum") return Uint8Array.of(Number(value ?? 0));
	if (spec.type === "bytes") return value instanceof Uint8Array ? value : new Uint8Array(0);
	return encoder.encode(typeof value === "string" ? value : "");
}

function encodeBody(
	fields: readonly FieldSpec[],
	message: Readonly<Record<string, unknown>>,
): Uint8Array {
	const parts = fields.map((spec) => {
		const value = message[spec.name];
		const given = givenError(spec, value);
		if (given) throw new WireEncodeError(spec.name, given);
		const bytes = bytesOf(spec, value);
		const error = checkField(spec, bytes);
		if (error) throw new WireEncodeError(spec.name, error);
		return bytes;
	});
	const out = new Uint8Array(parts.reduce((n, p) => n + 2 + p.length, 0));
	const view = new DataView(out.buffer);
	let at = 0;
	for (const part of parts) {
		view.setUint16(at, part.length);
		out.set(part, at + 2);
		at += 2 + part.length;
	}
	return out;
}

function frame(tag: number, id: number, body: Uint8Array, max: number): Uint8Array {
	if (body.length > max) throw new WireEncodeError("body", "length");
	const out = new Uint8Array(headerLength + body.length);
	const view = new DataView(out.buffer);
	out[0] = version;
	out[1] = tag;
	view.setUint32(2, id >>> 0);
	view.setUint32(6, body.length);
	out.set(body, headerLength);
	return out;
}

/** A request's frame, as the Front sends it; every field held to its spec, or a `WireEncodeError`. */
export function encodeRequest<K extends RequestKind>(
	kind: K,
	id: number,
	message: Message<K>,
): Uint8Array {
	const spec = requests[kind];
	return frame(
		spec.code,
		id,
		encodeBody(spec.fields, message as Record<string, unknown>),
		maxRequestBody,
	);
}

/** A reply's frame, as the Core sends it. */
export function encodeReply(reply: WireReply): Uint8Array {
	return frame(
		outcomes[reply.outcome],
		reply.id,
		encodeBody(replies[reply.outcome], reply.message as Record<string, unknown>),
		maxReplyBody,
	);
}

/** A header read: the kind's or outcome's byte, the id and the body's length. */
export type Header = {
	readonly ok: true;
	readonly tag: number;
	readonly id: number;
	readonly length: number;
};

/** A frame's header alone, so a wrong version or length is refused before its body is waited for. */
export function readHeader(bytes: Uint8Array, maxBody: number): Header | Rejected {
	const view = new DataView(bytes.buffer, bytes.byteOffset, headerLength);
	const id = view.getUint32(2);
	if (bytes[0] !== version) return { ok: false, error: "version", id: 0 };
	const length = view.getUint32(6);
	if (length > maxBody) return { ok: false, error: "length", id };
	return { ok: true, tag: bytes[1] ?? 0, id, length };
}

function decodeBody(
	fields: readonly FieldSpec[],
	body: Uint8Array,
): Record<string, unknown> | WireErrorName {
	const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
	const out: Record<string, unknown> = Object.create(null);
	let at = 0;
	for (const spec of fields) {
		if (at + 2 > body.length) return "truncated";
		const length = view.getUint16(at);
		at += 2;
		if (at + length > body.length) return "truncated";
		const bytes = body.subarray(at, at + length);
		at += length;
		const error = checkField(spec, bytes);
		if (error) return error;
		out[spec.name] =
			spec.type === "enum"
				? (bytes[0] ?? 0)
				: spec.type === "bytes"
					? new Uint8Array(bytes)
					: utf8.decode(bytes);
	}
	return at === body.length ? out : "trailing";
}

const kindOf = new Map<number, RequestKind>(
	(Object.keys(requests) as RequestKind[]).map((kind) => [requests[kind].code, kind]),
);
const outcomeOf = new Map<number, Outcome>(
	(Object.keys(outcomes) as Outcome[]).map((outcome) => [outcomes[outcome], outcome]),
);

/** One whole request frame, read without throwing: its kind and fields, or the code it is rejected with. */
export function decodeRequest(bytes: Uint8Array): Decoded<WireRequest> {
	if (bytes.length < headerLength) return { ok: false, error: "truncated", id: 0 };
	const header = readHeader(bytes, maxRequestBody);
	if (!header.ok) return header;
	const kind = kindOf.get(header.tag);
	if (kind === undefined) return { ok: false, error: "kind", id: header.id };
	const whole = headerLength + header.length;
	if (bytes.length !== whole)
		return { ok: false, error: bytes.length < whole ? "truncated" : "trailing", id: header.id };
	const message = decodeBody(requests[kind].fields, bytes.subarray(headerLength));
	if (typeof message === "string") return { ok: false, error: message, id: header.id };
	return { ok: true, value: { kind, id: header.id, message } as WireRequest };
}

/** One whole reply frame, read without throwing. */
export function decodeReply(bytes: Uint8Array): Decoded<WireReply> {
	if (bytes.length < headerLength) return { ok: false, error: "truncated", id: 0 };
	const header = readHeader(bytes, maxReplyBody);
	if (!header.ok) return header;
	const outcome = outcomeOf.get(header.tag);
	if (outcome === undefined) return { ok: false, error: "kind", id: header.id };
	const whole = headerLength + header.length;
	if (bytes.length !== whole)
		return { ok: false, error: bytes.length < whole ? "truncated" : "trailing", id: header.id };
	const message = decodeBody(replies[outcome], bytes.subarray(headerLength));
	if (typeof message === "string") return { ok: false, error: message, id: header.id };
	return { ok: true, value: { outcome, id: header.id, message } as WireReply };
}

/**
 * Cuts a stream into frames. A header whose version or length is wrong stops it at once, before its
 * body is waited for: `onError` is called once and nothing more is read, as the stream has lost its
 * place and the caller closes the connection.
 */
export function frameSplitter(
	maxBody: number,
	onFrame: (frame: Uint8Array) => void,
	onError: (error: WireErrorName, id: number) => void,
): (chunk: Uint8Array) => void {
	let held = new Uint8Array(0);
	let stopped = false;
	return (chunk) => {
		if (stopped) return;
		const joined = new Uint8Array(held.length + chunk.length);
		joined.set(held);
		joined.set(chunk, held.length);
		held = joined;
		while (held.length >= headerLength) {
			const header = readHeader(held, maxBody);
			if (!header.ok) {
				stopped = true;
				onError(header.error, header.id);
				return;
			}
			if (held.length < headerLength + header.length) return;
			onFrame(held.slice(0, headerLength + header.length));
			held = held.slice(headerLength + header.length);
		}
	};
}

/**
 * An operation's request as HTTP carries it: the body's values by name, in the order sent, and the
 * headers by lower-case name; and apart from them, the source the Front determined, none where it
 * determined none.
 */
export interface Carried {
	readonly values: ReadonlyMap<string, readonly string[]>;
	readonly headers: ReadonlyMap<string, string>;
	readonly source?: string;
}

/** A message read from HTTP, or the field it cannot carry and the code of why. */
export type Read<K extends RequestKind> =
	| { readonly ok: true; readonly message: Message<K> }
	| { readonly ok: false; readonly field: string; readonly error: WireErrorName };

const kinds = Object.keys(requests) as RequestKind[];
const sideOf = (kind: RequestKind): OverHttp => overHttp.operations[kind];
const nameOf = (side: OverHttp, field: string) => side.bodyNames?.[field] ?? field;
/** An enum value no text names is sent as this text, which no `texts` holds. */
const otherText = "other";
const base64url = /^[A-Za-z0-9_-]*$/;
const decimal = /^(0|[1-9][0-9]{0,2})$/;

/** The operation a request to `method` and `path` is, by the body value telling apart those sharing it; none where none is. */
export function operationAt(
	method: string,
	path: string,
	values: ReadonlyMap<string, readonly string[]>,
): RequestKind | undefined {
	if (method !== "POST") return undefined;
	const at = kinds.filter((kind) => sideOf(kind).path === path);
	const picked = at.find((kind) => {
		const discriminator = sideOf(kind).discriminator;
		const sent = discriminator && values.get(discriminator.name);
		return sent?.length === 1 && sent[0] === discriminator?.value;
	});
	return picked ?? at.find((kind) => !sideOf(kind).discriminator);
}

/** One field's value from its text, or the code of why it holds none. */
function fieldValue(
	spec: FieldSpec,
	side: OverHttp,
	text: string,
): { readonly value: unknown } | { readonly error: WireErrorName } {
	// A value carried as no text names nothing, whatever its type claims.
	if (typeof text !== "string") return { error: "fieldSyntax" };
	if (spec.type === "enum") {
		const texts = side.enumTexts?.[spec.name];
		const value = texts
			? Object.hasOwn(texts.texts, text)
				? texts.texts[text]
				: texts.other
			: decimal.test(text)
				? Number(text)
				: undefined;
		return value === undefined ? { error: "enumRange" } : { value };
	}
	if (spec.type !== "bytes") return { value: text };
	const bytes = base64url.test(text) ? Buffer.from(text, "base64url") : undefined;
	// Only the one text of its bytes: padding, or bits past the last byte, are refused.
	return bytes?.toString("base64url") === text
		? { value: new Uint8Array(bytes) }
		: { error: "fieldSyntax" };
}

/**
 * The message an operation's HTTP request carries, by `overHttp`: each field from its body name or its
 * header, a name sent more than once refused, and the declared source from `carried.source` alone,
 * never from the request. Each field's spec is the frame's encoder's to check after.
 */
export function messageOf<K extends RequestKind>(kind: K, carried: Carried): Read<K> {
	const side = sideOf(kind);
	const message: Record<string, unknown> = Object.create(null);
	for (const spec of requests[kind].fields as readonly FieldSpec[]) {
		if (spec.name === overHttp.declaredSource) {
			message[spec.name] = carried.source ?? "";
			continue;
		}
		const header = side.headerNames?.[spec.name];
		const sent = header
			? [carried.headers.get(header) ?? ""]
			: carried.values.get(nameOf(side, spec.name));
		if (sent && sent.length > 1) return { ok: false, field: spec.name, error: "fieldSyntax" };
		const read = fieldValue(spec, side, sent?.[0] ?? "");
		if ("error" in read) return { ok: false, field: spec.name, error: read.error };
		message[spec.name] = read.value;
	}
	return { ok: true, message: message as Message<K> };
}

/**
 * The message an operation's HTTP request carries, as `messageOf` reads it, then every field held
 * to its spec as the encoder holds it: what the Core's route reads before it acts on any field.
 */
export function requestOf<K extends RequestKind>(kind: K, carried: Carried): Read<K> {
	const read = messageOf(kind, carried);
	if (!read.ok) return read;
	for (const spec of requests[kind].fields as readonly FieldSpec[]) {
		const value = (read.message as Record<string, unknown>)[spec.name];
		const error = givenError(spec, value) ?? checkField(spec, bytesOf(spec, value));
		if (error) return { ok: false, field: spec.name, error };
	}
	return read;
}

/** One field's text, as `messageOf` reads it back. */
function textOf(spec: FieldSpec, side: OverHttp, value: unknown): string {
	if (spec.type === "bytes") return Buffer.from(value as Uint8Array).toString("base64url");
	if (spec.type !== "enum") return value as string;
	const texts = side.enumTexts?.[spec.name];
	if (!texts) return String(value);
	return Object.entries(texts.texts).find(([, v]) => v === value)?.[0] ?? otherText;
}

/** The HTTP request carrying a message, as the Core's route reads it: the value telling the operation apart first, then each field sent, an empty text not sent; the declared source apart, where there is one. */
export function carriedOf<K extends RequestKind>(kind: K, message: Message<K>): Carried {
	const side = sideOf(kind);
	const values = new Map<string, readonly string[]>();
	const headers = new Map<string, string>();
	let source: string | undefined;
	const { discriminator } = side;
	if (discriminator) values.set(discriminator.name, [discriminator.value]);
	for (const spec of requests[kind].fields as readonly FieldSpec[]) {
		const text = textOf(spec, side, (message as Record<string, unknown>)[spec.name]);
		if (text === "") continue;
		const header = side.headerNames?.[spec.name];
		if (spec.name === overHttp.declaredSource) source = text;
		else if (header) headers.set(header, text);
		else values.set(nameOf(side, spec.name), [text]);
	}
	return source === undefined ? { values, headers } : { values, headers, source };
}
