import {
	type Message,
	messageOf,
	operationAt,
	type RefusalWord,
	WireEncodeError,
	type WireReply,
} from "@mod/front-core-codec";
import { overHttp, type RequestKind, refusals } from "@mod/front-core-wire";

/** An HTTP request as a browser or a client sends it to the Front: a POST's path, its body's members and its headers. */
export interface Sent {
	readonly path: string;
	readonly body: Readonly<Record<string, string>>;
	readonly headers?: Readonly<Record<string, string>>;
}

/** What the Front answers a request with, as HTTP: the status, the body read as JSON, the DPoP nonce and Retry-After. */
export interface Answered {
	readonly status: number;
	readonly body: unknown;
	readonly dpopNonce?: string;
	readonly retryAfter?: string;
	/**
	 * The Core's reply as the wire carried it: none where nothing was sent. Not part of the HTTP
	 * answer: the harness reads it to tell the Core's refusal from the Front's.
	 */
	readonly wire?: WireReply;
}

/** The wire to the Core a Front holds: core-wire's `wireClient`, its replies by id. */
export interface Wire {
	send<K extends RequestKind>(kind: K, id: number, message: Message<K>): Promise<WireReply>;
}

/** A Front as a role uses it: it takes a request and answers it. */
export interface Front {
	post(sent: Sent): Promise<Answered>;
}

/** A request read as its operation and message, the source the Front declares its own. */
export type Read = {
	readonly [K in RequestKind]: { readonly kind: K; readonly message: Message<K> };
}[RequestKind];

const utf8 = new TextDecoder();
/**
 * The answer to a field its operation or the frame cannot carry, nothing sent, as front-relay answers
 * it: `400`, the word its refusal carries (front-core-codec's one rule), the field and its code.
 */
export const unsendableOf = (field: string, code: string, word: RefusalWord): Answered => ({
	status: 400,
	body: { error: word, error_description: `${field}: ${code}` },
});
const seconds = /^[0-9]{1,10}$/;

/**
 * Reads a request as its operation's message: none of an operation is `404`, a body the operation
 * cannot read `400` in its refusal's word (`unsendableOf`), as front-relay answers them. Its body's members are texts alone.
 */
export function read(sent: Sent, source: string): Read | { readonly answered: Answered } {
	const values = new Map(Object.entries(sent.body).map(([name, value]) => [name, [value]]));
	const kind = operationAt("POST", sent.path, values);
	if (kind === undefined) return { answered: { status: 404, body: undefined } };
	const headers = new Map(
		Object.entries(sent.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]),
	);
	const message = messageOf(kind, { values, headers, source, mistyped: new Set() });
	if (!message.ok) return { answered: unsendableOf(message.field, message.error, message.word) };
	return { kind, message: message.message } as Read;
}

/** Carries frames on one wire, each its own id in order, those relayed and any other alike. */
export function carrier(wire: Wire) {
	let id = 0;
	return {
		/** Sends a frame and reads its reply; a field outside its spec throws `WireEncodeError`, nothing sent. */
		send: <K extends RequestKind>(kind: K, message: Message<K>): Promise<WireReply> => {
			id += 1;
			return wire.send(kind, id, message);
		},
	};
}
export type Carrier = ReturnType<typeof carrier>;

/** Sends a frame, a field the frame cannot carry answered `400` in its refusal's word (`unsendableOf`), nothing sent. */
export async function sendOrRefuse<K extends RequestKind>(
	carry: Carrier,
	kind: K,
	message: Message<K>,
): Promise<WireReply | { readonly answered: Answered }> {
	try {
		return await carry.send(kind, message);
	} catch (error) {
		if (error instanceof WireEncodeError)
			return { answered: unsendableOf(error.field, error.code, error.word) };
		throw error;
	}
}

/** The reply as HTTP, as front-relay answers it: the success's status and body, a refusal's word and status, a rejection `502`. */
export function answerOf(kind: RequestKind, reply: WireReply): Answered {
	switch (reply.outcome) {
		case "ok": {
			const { body, dpopNonce } = reply.message;
			const text = utf8.decode(body);
			return {
				status: overHttp.operations[kind].successStatus ?? 200,
				body: text === "" ? undefined : JSON.parse(text),
				...(dpopNonce !== "" && { dpopNonce }),
			};
		}
		case "refused": {
			const { error, detail, dpopNonce, retryAfter } = reply.message;
			const word = refusals[error - 1] ?? "server_error";
			return {
				status: overHttp.statuses[word] ?? 400,
				body: detail ? { error: word, error_description: detail } : { error: word },
				...(dpopNonce !== "" && { dpopNonce }),
				...(seconds.test(retryAfter) && { retryAfter }),
			};
		}
		case "rejected":
			return { status: 502, body: { error: "server_error" } };
	}
}

/** An honest Front over a wire: each request read, sent as it came, its reply answered; the source it declares its own. */
export function honestRelay(wire: Wire, source: string): Front {
	const carry = carrier(wire);
	return {
		post: async (sent) => {
			const got = read(sent, source);
			if ("answered" in got) return got.answered;
			const reply = await sendOrRefuse(carry, got.kind, got.message as Message<typeof got.kind>);
			if ("answered" in reply) return reply.answered;
			return { ...answerOf(got.kind, reply), wire: reply };
		},
	};
}
