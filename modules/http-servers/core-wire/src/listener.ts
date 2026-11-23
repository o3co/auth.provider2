import type { AddressInfo } from "node:net";
import { createServer, type TLSSocket, type TlsOptions } from "node:tls";
import {
	decodeRequest,
	encodeReply,
	frameSplitter,
	type WireReply,
	type WireRequest,
} from "@mod/front-core-codec";
import { maxRequestBody, refusals, type WireErrorName, wireErrors } from "@mod/front-core-wire";
import type { Clock, Log } from "@mod/kernel";
import { type Detection, instanceOf } from "./detection.ts";

/** The wire's listener serving: the port it took, and its drain, cut short as the signal ends. */
export interface WireListening {
	readonly port: number;
	drain(signal: AbortSignal): Promise<void>;
}

export interface WireListener {
	/** Node's TLS server options, held to the floor, asking every peer for its certificate. */
	readonly tls: TlsOptions;
	readonly host: string;
	readonly port: number;
	readonly connections: number;
	/** The reply to a frame from the Front at `peer`'s address. */
	readonly handle: (request: WireRequest, peer: string) => Promise<WireReply>;
	readonly detection: Detection;
	readonly log: Log;
	readonly clock: Clock;
}

/** The longest a timer waits. */
const longest = 2 ** 31 - 1;
const failed = (id: number): WireReply => ({
	outcome: "refused",
	id,
	message: {
		error: refusals.indexOf("server_error") + 1,
		detail: "",
		dpopNonce: "",
		retryAfter: "",
	},
});

/**
 * Serves the wire on mutual TLS: each connection from a Front instance whose certificate the
 * authority issued, closed as that certificate expires; frames answered as they come, each by its id.
 * A frame rejected is answered with its code alone and ends the connection, nothing read after it.
 */
export async function listenWire(w: WireListener): Promise<WireListening> {
	let stopping = false;
	const inFlight = new Map<TLSSocket, number>();
	const server = createServer(w.tls, (socket) => {
		socket.on("error", () => {});
		const certificate = socket.getPeerCertificate();
		const instance = instanceOf(certificate);
		if (!w.detection.admits(instance)) {
			socket.destroy();
			return;
		}
		// A connection ending already, as a rejected one is, sends its last reply first.
		const forget = w.detection.connected(instance, () => {
			if (!socket.writableEnded) socket.destroy();
		});
		const left = Date.parse(certificate.valid_to) - w.clock.now();
		const expiry = setTimeout(() => socket.destroy(), Math.max(0, Math.min(left, longest)));
		inFlight.set(socket, 0);
		socket.once("close", () => {
			clearTimeout(expiry);
			forget();
			inFlight.delete(socket);
		});
		const peer = socket.remoteAddress ?? "";
		let rejected = false;
		const reject = (code: WireErrorName, id: number) => {
			if (rejected) return;
			rejected = true;
			socket.end(encodeReply({ outcome: "rejected", id, message: { code: wireErrors[code] } }));
			setTimeout(() => socket.destroy(), 1000).unref();
			w.detection.noticed(code, instance);
		};
		const settle = () => {
			const n = (inFlight.get(socket) ?? 1) - 1;
			inFlight.set(socket, n);
			if (stopping && n === 0) socket.end();
		};
		const onFrame = (frame: Uint8Array) => {
			if (rejected) return;
			const read = decodeRequest(frame);
			if (!read.ok) return reject(read.error, read.id);
			inFlight.set(socket, (inFlight.get(socket) ?? 0) + 1);
			void w
				.handle(read.value, peer)
				.then(encodeReply, (error: unknown) => {
					w.log.error("core-wire.failed", {
						kind: error instanceof Error ? error.name : typeof error,
					});
					return encodeReply(failed(read.value.id));
				})
				.then(
					(bytes) => {
						if (!socket.destroyed && !rejected) socket.write(bytes);
					},
					() => socket.destroy(),
				)
				.finally(settle);
		};
		const split = frameSplitter(maxRequestBody, onFrame, reject);
		socket.on("data", (chunk: Buffer) => split(chunk));
	});
	server.maxConnections = w.connections;
	// A peer refused at the handshake (no certificate, or not the authority's) is told at debug alone: anyone on the network can cause it.
	server.on("tlsClientError", () => w.log.debug("core-wire.handshake_refused", {}));
	server.listen(w.port, w.host);
	await new Promise<void>((resolve, reject) => {
		server.once("listening", resolve);
		server.once("error", reject);
	});
	return {
		port: (server.address() as AddressInfo).port,
		drain: (signal) => {
			stopping = true;
			const closed = new Promise<void>((resolve) => server.close(() => resolve()));
			for (const [socket, n] of inFlight) if (n === 0) socket.end();
			const cut = () => {
				for (const socket of inFlight.keys()) socket.destroy();
			};
			if (signal.aborted) cut();
			else signal.addEventListener("abort", cut, { once: true });
			return closed;
		},
	};
}
