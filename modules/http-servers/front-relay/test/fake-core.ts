import { readFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { createServer, type TLSSocket } from "node:tls";
import {
	decodeRequest,
	encodeReply,
	frameSplitter,
	type WireReply,
	type WireRequest,
} from "@mod/front-core-codec";
import { maxRequestBody } from "@mod/front-core-wire";
import type { CertificateFiles, WireCertificates } from "../src/testing.ts";

/** What the fake Core answers a request with; none leaves it unanswered. */
export type Answer = (request: WireRequest) => Unnumbered | undefined;
type Unnumbered = {
	[O in WireReply["outcome"]]: Omit<Extract<WireReply, { outcome: O }>, "id">;
}[WireReply["outcome"]];

/** A Core's entrance for tests: mTLS by the wire's authority, each request kept and answered as told. */
export async function fakeCore(
	certificates: WireCertificates,
	answer: Answer,
	shows: CertificateFiles = certificates.core,
) {
	const seen: WireRequest[] = [];
	const peers: string[] = [];
	const sockets = new Set<TLSSocket>();
	const server = createServer(
		{
			cert: await readFile(shows.cert),
			key: await readFile(shows.key),
			ca: await readFile(certificates.authority),
			requestCert: true,
			rejectUnauthorized: true,
		},
		(socket) => {
			sockets.add(socket);
			socket.once("close", () => sockets.delete(socket));
			peers.push(String(socket.getPeerCertificate().subjectaltname));
			socket.on(
				"data",
				frameSplitter(
					maxRequestBody,
					(frame) => {
						const read = decodeRequest(frame);
						if (!read.ok) return;
						seen.push(read.value);
						const reply = answer(read.value);
						if (reply) socket.write(encodeReply({ ...reply, id: read.value.id } as WireReply));
					},
					() => socket.destroy(),
				),
			);
		},
	);
	server.listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	return {
		port: (server.address() as AddressInfo).port,
		seen,
		peers,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise((resolve) => server.close(resolve));
		},
	};
}
