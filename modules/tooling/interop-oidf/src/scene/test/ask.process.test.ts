import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { expect, it } from "vitest";
import { ask } from "./ask.ts";

it("reaches an origin whose host this machine has no name for at the address given, trusting its certificate alone", async () => {
	const dir = await mkdtemp(join(tmpdir(), "interop-oidf-ask-"));
	const host = "issuer.example.invalid";
	const { key, cert } = await selfSigned(host, dir);
	const server = createServer({ key, cert }, (req, res) =>
		res.end(JSON.stringify({ host: req.headers.host })),
	);
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	try {
		const origin = `https://${host}:${(server.address() as AddressInfo).port}`;
		const answer = await ask({ origin, certificate: cert, address: "127.0.0.1" }, "/x");
		expect(answer.status).toBe(200);
		expect(answer.json.host).toBe(new URL(origin).host);
		// Without it the host is looked up, and this machine has no name for it (the first socket
		// closed, so the agent keeps none to reuse).
		server.closeAllConnections();
		await expect(ask({ origin, certificate: cert }, "/x")).rejects.toThrow(/ENOTFOUND/);
	} finally {
		server.close();
		await rm(dir, { recursive: true, force: true });
	}
}, 60_000);

it("fails a request past its time, and one whose answer is cut off, never waiting on", async () => {
	const dir = await mkdtemp(join(tmpdir(), "interop-oidf-ask-"));
	const { key, cert } = await selfSigned("localhost", dir);
	const server = createServer({ key, cert }, (req, res) => {
		if (req.url === "/cut") {
			res.writeHead(200, { "content-length": "100" });
			res.write("partial");
			setTimeout(() => res.destroy(), 50);
		}
		if (req.url === "/trickle") {
			res.writeHead(200, { "content-length": "1000" });
			const drip = setInterval(() => res.write("."), 50);
			res.on("close", () => clearInterval(drip));
		}
		// "/silent" is never answered.
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	try {
		const at = {
			origin: `https://localhost:${(server.address() as AddressInfo).port}`,
			certificate: cert,
		};
		await expect(ask(at, "/silent", { withinMs: 200 })).rejects.toThrow(
			"no answer within its time",
		);
		await expect(ask(at, "/cut")).rejects.toThrow();
		// Its time is the whole request's, however the answer trickles in.
		await expect(ask(at, "/trickle", { withinMs: 300 })).rejects.toThrow(
			"no answer within its time",
		);
	} finally {
		server.closeAllConnections();
		server.close();
		await rm(dir, { recursive: true, force: true });
	}
}, 60_000);
