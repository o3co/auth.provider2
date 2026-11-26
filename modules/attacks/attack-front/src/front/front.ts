import {
	type Message,
	messageOf,
	operationAt,
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
	 * The Core's reply as the wire carried it, before any rewrite: none where nothing was sent. Not
	 * part of the HTTP answer: the harness reads it to tell the Core's refusal from the Front's.
	 */
	readonly wire?: WireReply;
}

/** The wire to the Core a Front holds: core-wire's `wireClient`, its replies by id. */
export interface Wire {
	send<K extends RequestKind>(kind: K, id: number, message: Message<K>): Promise<WireReply>;
}

/** A step's change to what the Front relays: each operation's message before it goes, each reply before it is answered. */
export interface Rewrites {
	/** Each operation's message before it goes, now or once worked out (a Front may compute its change). */
	readonly messages?: {
		readonly [K in RequestKind]?: (message: Message<K>) => Message<K> | Promise<Message<K>>;
	};
	readonly replies?: { readonly [K in RequestKind]?: (reply: WireReply) => WireReply };
}

/** A frame the Front sent and the reply it read: all a Front sees. */
export interface Relayed {
	readonly kind: RequestKind;
	readonly message: Message<RequestKind>;
	readonly reply: WireReply;
}

const utf8 = new TextDecoder();
const invalidRequest: Answered = { status: 400, body: { error: "invalid_request" } };

const seconds = /^[0-9]{1,10}$/;

/** The reply as HTTP, as the honest Front (`front-relay`) answers it: the success's status and body, a refusal's word and status, a rejection `502`. */
function answerOf(kind: RequestKind, reply: WireReply): Answered {
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

/**
 * A dishonest Front: it relays every request as the honest one does, the source it declares its own,
 * and changes what the step's rewrites say. It sees every frame and reply, and may send frames of its
 * own. It holds no screen's or relying party's key.
 */
export function badFront(wire: Wire, source: string) {
	let id = 0;
	let rewrites: Rewrites = {};
	const seen: Relayed[] = [];
	const send = async <K extends RequestKind>(kind: K, message: Message<K>) => {
		id += 1;
		const reply = await wire.send(kind, id, message);
		seen.push({ kind, message: message as Message<RequestKind>, reply });
		return reply;
	};
	const relay = async <K extends RequestKind>(
		kind: K,
		values: ReadonlyMap<string, readonly string[]>,
		headers: ReadonlyMap<string, string>,
	): Promise<Answered> => {
		// The rewrites as they stand when the request comes: one setting for its message and its reply.
		const now = rewrites;
		// Its requests' bodies are texts alone: none is sent as no text.
		const read = messageOf(kind, { values, headers, source, mistyped: new Set() });
		if (!read.ok) return invalidRequest;
		const change = now.messages?.[kind] as
			| ((message: Message<K>) => Message<K> | Promise<Message<K>>)
			| undefined;
		let reply: WireReply;
		try {
			reply = await send(kind, change ? await change(read.message) : read.message);
		} catch (error) {
			// A field outside its spec: the frame cannot carry it, so nothing is sent.
			if (error instanceof WireEncodeError) return invalidRequest;
			throw error;
		}
		return { ...answerOf(kind, now.replies?.[kind]?.(reply) ?? reply), wire: reply };
	};
	return {
		/** Relays a request: read as its operation, rewritten, sent, and its reply rewritten and answered. */
		post: async (sent: Sent): Promise<Answered> => {
			const values = new Map(Object.entries(sent.body).map(([name, value]) => [name, [value]]));
			const kind = operationAt("POST", sent.path, values);
			if (kind === undefined) return { status: 404, body: undefined };
			const headers = new Map(
				Object.entries(sent.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]),
			);
			return relay(kind, values, headers);
		},
		/** Sends a frame of the Front's own making. */
		send,
		/** Sets the step's rewrites, replacing the last. */
		rewrite: (next: Rewrites) => {
			rewrites = next;
		},
		/** Every frame sent and its reply, in order. */
		seen: (): readonly Relayed[] => seen,
	};
}

export type BadFront = ReturnType<typeof badFront>;
