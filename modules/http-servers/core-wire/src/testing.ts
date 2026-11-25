import { readFile } from "node:fs/promises";
import { connect, type TLSSocket } from "node:tls";
import {
	decodeReply,
	encodeRequest,
	frameSplitter,
	type Message,
	type WireReply,
} from "@mod/front-core-codec";
import { maxReplyBody, type RequestKind } from "@mod/front-core-wire";

/** The Core's certificate and the authority of the Fronts' ones, as the paths of their PEM files. */
export interface CoreCertificates {
	readonly authority: string;
	readonly core: { readonly cert: string; readonly key: string };
}

/** For tests: the `core-wire` part of a test's configuration, the probe listener on any free port, unless the test sets its own. */
export function coreWireConfig(
	certificates: CoreCertificates,
	settings: Record<string, unknown> = {},
) {
	return {
		"core-wire": {
			"certificate-file": certificates.core.cert,
			"key-file": certificates.core.key,
			"front-authority-file": certificates.authority,
			"probe-port": 0,
			...settings,
		},
	};
}

/** The authority the Core's certificate chains to and a Front instance's certificate, as the paths of their PEM files. */
export interface FrontCertificates {
	readonly authority: string;
	readonly front: { readonly cert: string; readonly key: string };
}

/** For tests: a Front's connection to the Core on localhost, showing `shows`, sending frames and keeping the replies by id. */
export async function wireClient(
	port: number,
	certificates: FrontCertificates,
	shows: FrontCertificates["front"] | "none" = certificates.front,
) {
	const replies = new Map<number, WireReply>();
	const waiters = new Map<number, (reply: WireReply) => void>();
	const socket: TLSSocket = connect({
		host: "127.0.0.1",
		port,
		ca: await readFile(certificates.authority),
		...(shows !== "none" && { cert: await readFile(shows.cert), key: await readFile(shows.key) }),
	});
	const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
	socket.on("error", () => {});
	// What the Core ends, the Front ends too.
	socket.on("end", () => socket.destroy());
	socket.on(
		"data",
		frameSplitter(
			maxReplyBody,
			(frame) => {
				const read = decodeReply(frame);
				if (!read.ok) return;
				replies.set(read.value.id, read.value);
				waiters.get(read.value.id)?.(read.value);
			},
			() => socket.destroy(),
		),
	);
	const reply = (id: number) =>
		new Promise<WireReply>((resolve) => {
			const kept = replies.get(id);
			if (kept) resolve(kept);
			else waiters.set(id, resolve);
		});
	return {
		socket,
		closed,
		send: <K extends RequestKind>(kind: K, id: number, message: Message<K>) => {
			socket.write(encodeRequest(kind, id, message));
			return reply(id);
		},
		raw: (bytes: Uint8Array, id: number) => {
			socket.write(bytes);
			return reply(id);
		},
		close: () => {
			socket.destroy();
		},
	};
}
