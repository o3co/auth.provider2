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
import type { CertificateFiles, WireCertificates } from "@mod/front-relay/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { assemble, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import coreWire from "../src/module.ts";
import { coreWireConfig } from "../src/testing.ts";

/** A Core of these modules behind core-wire, started, trusting the Fronts on localhost; its wire port, its probe port and its log. */
export async function core(
	certificates: WireCertificates,
	modules: readonly Module[],
	settings: Record<string, unknown> = {},
	httpSettings: Record<string, unknown> = { "trusted-proxies": ["127.0.0.1"] },
) {
	const recorded = recordingLog();
	const app = await assemble({
		modules: [http, tlsOptionsForTests, coreWire, ...modules],
		config: {
			...kernelConfig(),
			http: { port: 0, ...httpSettings },
			...coreWireConfig(certificates, settings),
		},
		runtime: quietRuntime({ log: recorded.log }),
	});
	await app.start();
	const probe = recorded.lines().find((l) => l.event === "core-wire.probe_listening");
	return {
		port: app.get(listening).port(),
		probePort: Number(probe?.fields?.port),
		lines: recorded.lines,
		stop: () => app.stop(1000),
	};
}

/** A Front's connection to the Core, sending frames and keeping the replies by id. */
export async function wireClient(
	port: number,
	certificates: WireCertificates,
	shows: CertificateFiles | "none" = certificates.front,
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

export const tokenMessage = (code = "abc", source = "203.0.113.5"): Message<"token"> => ({
	source,
	grantType: 1,
	code,
	redirectUri: "https://rp.example/cb",
	codeVerifier: "v".repeat(43),
	clientAssertionType: 1,
	clientAssertion: "a.b.c",
	clientId: "",
	authorizationDetails: 0,
	dpop: "d.e.f",
});
