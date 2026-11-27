import { createPublicKey, type KeyObject } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { connect, createServer as createTcpServer, type Socket } from "node:net";
import { join } from "node:path";
import { type FakeLedger, passkeyWitnessLedger, usersLedger } from "@mod/ledger-fakes";
import { fakeRelay } from "@mod/mail-smtp/testing";
import { passkeyWitnessHttpConfig } from "@mod/passkey-witness-http/testing";
import { usersHttpConfig } from "@mod/users-http/testing";
import { firstKey, screenKeys } from "@sdk/login-screen";
import { describe, expect, it } from "vitest";
import { freePort, type Running } from "../src/testing.ts";
import {
	bootMs,
	coreAndFront,
	events,
	heldFixtures,
	memoryCore,
	sealing,
	sentThrough,
	throughFront,
} from "./held.ts";

// The flip's evidence, E3b (permission-model-plan.md, "The flip's evidence: plan"): a first key's
// mail, the one mail the generated Core sends, from a Core composed with an outside user ledger
// (users-http, its witness passkey-witness-http), run through the manifest's `start` under audit (the
// held line, no event line, the mail at the relay) and under enforce (the same). It reads the login
// screen's SDK, so it is typed by tsconfig.sdk-tests.json (the DOM's types), apart from
// held.process.test.ts: Node's and the DOM's CryptoKey types collide in x509-path's testing helpers,
// which that file reads. The fakes and the held runs are held.ts's.

heldFixtures();

/** Fake ledgers served on loopback (127.0.0.1, a port of their own), each call handed to them whole. */
async function ledgersServed(ledgers: readonly FakeLedger<string, string>[]) {
	const server = createServer((request, response) => {
		let body = "";
		request.on("data", (chunk) => {
			body += chunk;
		});
		request.on("end", () => {
			const headers = Object.fromEntries(
				Object.entries(request.headers).map(([name, value]) => [
					name,
					Array.isArray(value) ? value.join(", ") : value,
				]),
			);
			const call = { method: request.method ?? "", path: request.url ?? "", headers, body };
			const answer = ledgers.map((ledger) => ledger.answer(call)).find(Boolean) ?? { status: 404 };
			const json = answer.json === undefined ? "" : JSON.stringify(answer.json);
			response
				.writeHead(answer.status ?? 200, json ? { "content-type": "application/json" } : {})
				.end(json);
		});
	});
	const port = await new Promise<number>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
	});
	return { port, close: () => new Promise<void>((done) => server.close(() => done())) };
}

/** The one user the outside ledger holds: no passkey, its mail verified. */
const ana = {
	identifier: "ana@mail.example",
	subject: "1".padStart(32, "0"),
	email: "ana@mail.example",
	emailVerified: true,
} as const;

/**
 * The relay reached at IPv6's loopback (::1, a port of its own), each connection carried to it at
 * 127.0.0.1: the model names a connection's host alone, never its port, and the Core reaches KMS and
 * the ledgers at 127.0.0.1, so only the send to the relay names ::1. Closed whole by `close`.
 */
async function relayAtIpv6() {
	const relay = await fakeRelay();
	const sockets = new Set<Socket>();
	const server = createTcpServer((client) => {
		const upstream = connect(relay.port, "127.0.0.1");
		for (const socket of [client, upstream]) {
			sockets.add(socket);
			socket.on("error", () => {
				client.destroy();
				upstream.destroy();
			});
		}
		client.pipe(upstream).pipe(client);
	});
	const close = async () => {
		for (const socket of sockets) socket.destroy();
		await new Promise<void>((done) => server.close(() => done()));
		await relay.close();
	};
	try {
		const port = await new Promise<number>((resolve, reject) => {
			server.once("error", reject);
			server.listen(0, "::1", () => resolve((server.address() as { port: number }).port));
		}).catch((error: NodeJS.ErrnoException) => {
			// No IPv6 loopback is the environment's fault, never a pass: the control needs ::1.
			throw new Error(
				`::1 cannot be bound (${error.code ?? error.message}): this host has no IPv6 loopback`,
			);
		});
		return { relay, port, close };
	} catch (error) {
		await relay.close();
		throw error;
	}
}

/** The outside ledgers: the user ledger holding `ana`, and the passkey witness's. */
const outsideLedgers = () => ({ users: usersLedger([ana]), witness: passkeyWitnessLedger() });

/**
 * The Core's configuration with users-http and passkey-witness-http over the ledgers served at
 * `ledgerPort`, its mail to the relay at [::1]:`relayPort`.
 */
function ledgerCore(
	port: number,
	relayPort: number,
	ledgerPort: number,
	ledgers: ReturnType<typeof outsideLedgers>,
) {
	const { "users-local": _local, ...base } = memoryCore(port);
	const at = `127.0.0.1:${ledgerPort}`;
	return {
		...base,
		"mail-smtp": { ...(base["mail-smtp"] as object), host: "::1", port: relayPort },
		...usersHttpConfig({
			"verify-url": `http://${at}/verify`,
			"subject-url": `http://${at}/subject`,
			"identifier-url": `http://${at}/identifier`,
			credential: ledgers.users.credential,
		}),
		...passkeyWitnessHttpConfig({
			"read-url": `http://${at}/passkey-witness/read`,
			"enroll-url": `http://${at}/passkey-witness/enroll`,
			"withdraw-url": `http://${at}/passkey-witness/withdraw`,
			credential: ledgers.witness.credential,
		}),
		outbound: {
			...(base.outbound as { allow: string[] }),
			allow: [...(base.outbound as { allow: string[] }).allow, "127.0.0.1"],
			"plain-loopback": [at],
		},
	};
}

/** The sealing key's public point, raw (HPKE's P-256 form), as the screen's bundle fixes it. */
const rawPoint = (key: KeyObject) => {
	const { x, y } = createPublicKey(key).export({ format: "jwk" });
	return new Uint8Array([
		4,
		...Buffer.from(x ?? "", "base64url"),
		...Buffer.from(y ?? "", "base64url"),
	]);
};

/** A first key's start through the Front, as the screen makes it: its nonce, the identifier sealed to the Core. */
async function firstKeyStarted(frontPort: number, identifier: string, coreRun: Running) {
	const nonced = await sentThrough(frontPort, "/first-key/nonce", {
		type: "application/json",
		body: JSON.stringify({ stage: "start" }),
	});
	expect(nonced.status, coreRun.out()).toBe(200);
	const { nonce } = (await nonced.json()) as { nonce: string };
	const keys = await screenKeys();
	const made = await firstKey.start({ identifier }, nonce, {
		ring: [],
		sealingKey: rawPoint(sealing),
		keys,
		issuer: "https://issuer.example.invalid",
	});
	if ("error" in made) throw new Error(`firstKey.start: ${made.error}`);
	const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
	const started = await sentThrough(frontPort, "/first-key/start", {
		type: "application/json",
		body: JSON.stringify({
			nonce,
			eEnc: keys.eEnc,
			eSigX: keys.eSig.x,
			eSigY: keys.eSig.y,
			enc: b64url(made.sealed.enc),
			ct: b64url(made.sealed.ct),
		}),
	});
	expect(started.status, coreRun.out()).toBe(200);
}

/** A message's text with its quoted-printable body read back (RFC 2045 §6.7): soft breaks joined, octets decoded. */
const readBack = (message: string) =>
	Buffer.from(
		message
			.replace(/=\r?\n/g, "")
			.replace(/=([0-9A-F]{2})/g, (_, hex: string) =>
				String.fromCharCode(Number.parseInt(hex, 16)),
			),
		"latin1",
	).toString("utf8");

/** The relay got one mail, to `ana`, carrying the first key's link. */
function mailedToAna(relay: Awaited<ReturnType<typeof fakeRelay>>) {
	expect(relay.lines).toContain(`RCPT TO:<${ana.identifier}>`);
	expect(relay.messages).toHaveLength(1);
	const text = readBack(relay.messages[0] ?? "");
	expect(text).toContain(`To: <${ana.identifier}>`);
	// The link carries the mail's token after its fragment mark.
	expect(text).toMatch(/https:\/\/login\.example\.invalid\/first-key#\S+/);
}

/** A Node holding the network (one taking --allow-net): only there is a connection told. */
const holdsNet = process.allowedNodeEnvironmentFlags.has("--allow-net");

describe("a generated Core held while it sends a first key's mail (the flip's evidence, E3b: Node 26 alone holds its network)", () => {
	// Node 26 holds the network on or off, never per host: which relay the mail goes to is mail-smtp's
	// own configuration, not the model's. A refusal of the send alone under enforce cannot be staged,
	// as the same switch holds the Core's listen. The first case (no event under enforce) and the
	// control after it (the send told when the network is withheld) together show the send goes
	// through the model and needs no grant beyond the generated set.
	const outside = { axes: { "@mod/users": "@mod/users-http" }, add: ["@mod/passkey-witness-http"] };

	it(
		"nextgen-core with users-http: a first key's start through the Front, its user looked up in the outside ledger, its mail sent over SMTP; no event under audit, the same under enforce",
		() =>
			coreAndFront(async ({ core, front }) => {
				const ledgers = outsideLedgers();
				const served = await ledgersServed([ledgers.users, ledgers.witness]);
				const relayed = await relayAtIpv6().catch(async (error) => {
					await served.close();
					throw error;
				});
				try {
					const config = ledgerCore(await freePort(), relayed.port, served.port, ledgers);
					for (const mode of ["audit", "enforce"] as const) {
						relayed.relay.lines.length = 0;
						relayed.relay.messages.length = 0;
						await throughFront(
							core,
							front,
							config,
							mode,
							(frontPort, coreRun) => firstKeyStarted(frontPort, ana.identifier, coreRun),
							() => relayed.relay.messages.length > 0,
						);
						mailedToAna(relayed.relay);
					}
				} finally {
					await relayed.close();
					await served.close();
				}
			}, outside),
		4 * bootMs + 2 * 10_000,
	);

	it.runIf(holdsNet)(
		"nextgen-core with users-http: with the Core's network withheld, audit tells the connection to the relay, and the mail still arrives",
		() =>
			coreAndFront(async ({ core, front }) => {
				const ledgers = outsideLedgers();
				const served = await ledgersServed([ledgers.users, ledgers.witness]);
				const relayed = await relayAtIpv6().catch(async (error) => {
					await served.close();
					throw error;
				});
				try {
					const file = join(core.dir, "permissions.json");
					const kept = await readFile(file, "utf8");
					try {
						const config = ledgerCore(await freePort(), relayed.port, served.port, ledgers);
						const withheld = JSON.parse(kept);
						withheld.processes.start.network = false;
						await writeFile(file, JSON.stringify(withheld));
						const out = await throughFront(
							core,
							front,
							config,
							"audit",
							(frontPort, coreRun) => firstKeyStarted(frontPort, ana.identifier, coreRun),
							() => relayed.relay.messages.length > 0,
							{},
							"some",
						);
						// One send, one connection to ::1, the relay's address alone: at least one event names
						// it, as a connection may be told more than once.
						const toRelay = events(out).filter((line) => line.includes('"resource":"::1"'));
						expect(toRelay.length, out).toBeGreaterThanOrEqual(1);
						mailedToAna(relayed.relay);
					} finally {
						await writeFile(file, kept);
					}
				} finally {
					await relayed.close();
					await served.close();
				}
			}, outside),
		2 * bootMs + 10_000,
	);
});
