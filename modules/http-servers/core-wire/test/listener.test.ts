import { readFile } from "node:fs/promises";
import type { WireReply } from "@mod/front-core-codec";
import { refusals } from "@mod/front-core-wire";
import { type WireCertificates, wireCertificates } from "@mod/front-relay/testing";
import { recordingLog } from "@mod/kernel/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
import { detection } from "../src/detection.ts";
import { listenWire } from "../src/listener.ts";
import { wireClient } from "../src/testing.ts";
import { tokenMessage } from "./boot.ts";

let certificates: WireCertificates;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());

it("answers a frame whose reply will not encode server_error alone, a frame in flight beside it and the frames after it answered on the same connection", async () => {
	const recorded = recordingLog();
	const clock = { now: () => Date.now() };
	let release: () => void = () => {};
	const held = new Promise<void>((resolve) => {
		release = resolve;
	});
	const answer = (id: number, detail: string) =>
		({
			outcome: "refused",
			id,
			message: {
				error: refusals.indexOf("invalid_request") + 1,
				detail,
				dpopNonce: "",
				retryAfter: "",
			},
		}) as WireReply;
	const wire = await listenWire({
		tls: {
			cert: await readFile(certificates.core.cert),
			key: await readFile(certificates.core.key),
			ca: await readFile(certificates.authority),
			requestCert: true,
		},
		host: "127.0.0.1",
		port: 0,
		connections: 4,
		// Frame 1 is held in flight; frame 2's reply is off the wire's form (a detail no well-formed text
		// spells); every other is answered as it should be.
		handle: async (request) => {
			if (request.id === 1) await held;
			return answer(request.id, request.id === 2 ? "\ud800" : "fine");
		},
		detection: detection("notify", recorded.log, clock),
		log: recorded.log,
		clock,
	});
	const front = await wireClient(wire.port, certificates);
	try {
		const bystander = front.send("token", 1, tokenMessage());
		const bad = await front.send("token", 2, tokenMessage());
		expect(bad).toMatchObject({
			outcome: "refused",
			id: 2,
			message: { error: refusals.indexOf("server_error") + 1 },
		});
		release();
		expect(await bystander).toMatchObject({
			outcome: "refused",
			id: 1,
			message: { detail: "fine" },
		});
		expect(await front.send("token", 3, tokenMessage())).toMatchObject({
			id: 3,
			message: { detail: "fine" },
		});
		expect(front.socket.destroyed).toBe(false);
		// Logged by the field and the code the encoder refused, never the value.
		expect(recorded.lines().filter((l) => l.event === "core-wire.failed")).toEqual([
			{
				level: "error",
				event: "core-wire.failed",
				fields: { kind: "reply_unencodable", field: "detail", code: "fieldSyntax" },
			},
		]);
	} finally {
		front.close();
		await wire.drain(AbortSignal.abort());
	}
});
