import { type Message, WireEncodeError, type WireReply } from "@mod/front-core-codec";
import type { RequestKind } from "@mod/front-core-wire";
import {
	type Answered,
	answerOf,
	type Carrier,
	carrier,
	read,
	type Sent,
	sendOrRefuse,
	unsendable,
	type Wire,
} from "../relay/relay.ts";

export type { Answered, Sent, Wire };

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

/**
 * A dishonest Front: it relays every request as the honest one does, the source it declares its own,
 * and changes what the step's rewrites say. It sees every frame and reply, and may send frames of its
 * own. It holds no screen's or relying party's key.
 */
export function badFront(wire: Wire, source: string) {
	const carry = carrier(wire);
	let rewrites: Rewrites = {};
	const seen: Relayed[] = [];
	// Every frame on its wire, relayed or its own, kept with the reply as it came.
	const send = async <K extends RequestKind>(kind: K, message: Message<K>) => {
		const reply = await carry.send(kind, message);
		seen.push({ kind, message: message as Message<RequestKind>, reply });
		return reply;
	};
	const kept: Carrier = { send };
	return {
		/** Relays a request: read as its operation, rewritten, sent, and its reply rewritten and answered. */
		post: async (sent: Sent): Promise<Answered> => {
			// The rewrites as they stand when the request comes: one setting for its message and its reply.
			const now = rewrites;
			const got = read(sent, source);
			if ("answered" in got) return got.answered;
			const kind = got.kind;
			const change = now.messages?.[kind] as
				| ((message: Message<typeof kind>) => Message<typeof kind> | Promise<Message<typeof kind>>)
				| undefined;
			const asRead = got.message as Message<typeof kind>;
			let message: Message<typeof kind>;
			try {
				message = change ? await change(asRead) : asRead;
			} catch (error) {
				// A rewrite's message the frame cannot carry: nothing is sent, as for the request's own.
				if (error instanceof WireEncodeError) return unsendable;
				throw error;
			}
			const reply = await sendOrRefuse(kept, kind, message);
			if ("answered" in reply) return reply.answered;
			return { ...answerOf(kind, now.replies?.[kind]?.(reply) ?? reply), wire: reply };
		},
		/** Sends a frame of the Front's own making, unrewritten. */
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
