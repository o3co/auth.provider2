import { type ConnectionOptions, connect, type TLSSocket } from "node:tls";
import {
	decodeReply,
	encodeRequest,
	frameSplitter,
	type Message,
	type WireReply,
} from "@mod/front-core-codec";
import { maxReplyBody, type RequestKind } from "@mod/front-core-wire";
import { type Log, Unavailable } from "@mod/kernel";

/** The Front's one connection to the Core's entrance, over which every relayed frame goes and its reply comes back. */
export interface CoreLink {
	/**
	 * The Core's reply to one operation's message. A field outside its spec throws `WireEncodeError`,
	 * sending nothing; no connection, no reply in time, or a connection lost throws Unavailable.
	 */
	send<K extends RequestKind>(kind: K, message: Message<K>): Promise<WireReply>;
	/** Resolves once a connection is open, rejecting where none opens before the signal aborts. */
	reach(signal: AbortSignal): Promise<void>;
	/** Closes the connection; what waits fails as Unavailable, and nothing connects after. */
	close(): void;
}

interface Waiting {
	settle(reply: WireReply): void;
	fail(error: Error): void;
}

const unavailable = () => new Unavailable("core");

/**
 * A link connecting when first needed, with the options `optionsOf` gives at each connection (so a
 * rotated certificate is read anew), each request waiting `timeoutMs` at most for its reply. A reply
 * that is no frame closes the connection, logged by its code alone.
 */
export function coreLink(
	optionsOf: () => Promise<ConnectionOptions>,
	timeoutMs: number,
	log: Log,
): CoreLink {
	let open: Promise<TLSSocket> | undefined;
	let closed = false;
	let last = 0;
	const waiting = new Map<number, Waiting>();
	/** Each socket's connection, so a socket closing clears only its own. */
	const opened = new WeakMap<TLSSocket, Promise<TLSSocket>>();
	const failAll = () => {
		for (const w of waiting.values()) w.fail(unavailable());
		waiting.clear();
	};
	const onFrame = (socket: TLSSocket) => (frame: Uint8Array) => {
		const read = decodeReply(frame);
		if (!read.ok) {
			log.error("front-relay.reply_unreadable", { code: read.error });
			socket.destroy();
			return;
		}
		const w = waiting.get(read.value.id);
		waiting.delete(read.value.id);
		w?.settle(read.value);
	};
	const opening = (options: ConnectionOptions) =>
		new Promise<TLSSocket>((resolve, reject) => {
			const socket = connect(options);
			// The handshake, too, waits no longer than a reply does.
			socket.setTimeout(timeoutMs, () => socket.destroy());
			socket.on("error", () => {});
			socket.once("close", () => {
				reject(unavailable());
				if (opened.get(socket) === open) open = undefined;
				failAll();
			});
			socket.once("secureConnect", () => {
				socket.setTimeout(0);
				resolve(socket);
			});
			const split = frameSplitter(maxReplyBody, onFrame(socket), (code) => {
				log.error("front-relay.reply_unreadable", { code });
				socket.destroy();
			});
			socket.on("data", (chunk: Buffer) => split(chunk));
			if (open) opened.set(socket, open);
		});
	const connection = (): Promise<TLSSocket> => {
		if (closed) return Promise.reject(unavailable());
		if (!open) {
			const made = optionsOf().then(opening, () => Promise.reject(unavailable()));
			open = made;
			made.catch(() => {
				if (open === made) open = undefined;
			});
		}
		return open;
	};
	const nextId = () => {
		do last = (last % 0xffffffff) + 1;
		while (waiting.has(last));
		return last;
	};
	return {
		send: async (kind, message) => {
			const id = nextId();
			const frame = encodeRequest(kind, id, message);
			return new Promise<WireReply>((resolve, reject) => {
				const timer = setTimeout(() => {
					waiting.delete(id);
					reject(unavailable());
				}, timeoutMs);
				const done = () => {
					clearTimeout(timer);
					waiting.delete(id);
				};
				waiting.set(id, {
					settle: (reply) => {
						done();
						resolve(reply);
					},
					fail: (error) => {
						done();
						reject(error);
					},
				});
				connection().then(
					(socket) => {
						if (waiting.has(id)) socket.write(frame);
					},
					() => waiting.get(id)?.fail(unavailable()),
				);
			});
		},
		reach: (signal) =>
			new Promise<void>((resolve, reject) => {
				if (signal.aborted) reject(unavailable());
				signal.addEventListener("abort", () => reject(unavailable()), { once: true });
				connection().then(() => resolve(), reject);
			}),
		close: () => {
			closed = true;
			void open?.then(
				(socket) => socket.destroy(),
				() => {},
			);
			failAll();
		},
	};
}
