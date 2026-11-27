import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { promiseNames } from "@mod/promises";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	signedMachine,
	signedUriMachine,
	uriMachine,
	uriRelyingParty,
} from "../../pattern/test/clients.ts";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import { type MachineClient, machineClient } from "../../roles/test/machine.ts";
import { relyingParty } from "../../roles/test/rp.ts";
import { provider, type World, world } from "./world.ts";

// F-11's other half: a client whose keys are at a key set's URL. The Front has no way to answer that
// fetch (the Core makes it itself: F-11 in client-credentials.process.test.ts); this is what the Core
// does with such a client. A registered one breaks claim 2, so the harness's Core is refused at boot;
// behind that, in a composition not holding claim 2, client-credentials issues nothing on a key so had
// (R8); and a source's client naming one has no key, nothing fetched.

const api = "https://api.example";
let server: Server;
let fetched = 0;
let url = "";
const machine: MachineClient = machineClient("svc-uri", provider);
/** Another client signing with the very key the URL serves, written in its record: the control. */
const inline: MachineClient = machineClient("svc-inline", provider, machine.key);
/** A client the operator registers signing with the same key, the URL its key set. */
const registeredMachine: MachineClient = machineClient("svc-registered", provider, machine.key);

beforeAll(async () => {
	// The clients' key set, served where they publish it: the one key both sign with, under each one's kid.
	server = createServer((_request, response) => {
		fetched += 1;
		response.setHeader("content-type", "application/json");
		response.end(JSON.stringify({ keys: [machine.publicKey, registeredMachine.publicKey] }));
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks`;
});
afterAll(async () => {
	await new Promise<void>((resolve) => server?.close(() => resolve()));
});

/** The operator's outbound, letting the Core reach the key set's URL: no refusal is outbound's. */
const reaching = () => ({ allow: ["127.0.0.1"], "plain-loopback": [new URL(url).host] });

describe("F-11: a client's keys at a key set's URL", () => {
	it(
		"a registered client naming one breaks claim 2: boot is refused, its jwks-uri named by its place",
		async () => {
			const rp = relyingParty(provider, "rp-uri", "https://rp-uri.example/cb");
			const refused = await world([], {
				clients: [await uriRelyingParty(rp, url)],
				outbound: reaching(),
			}).then(
				async (booted) => {
					await booted.stop();
					return "";
				},
				(error: Error) => error.message,
			);
			const { refusals } = JSON.parse(refused.replace("the Core did not start: ", "") || "{}") as {
				refusals?: { where: string; reason: string }[];
			};
			// Claim 2's refusal alone: client-assertion's boot check of the URL against outbound passed, so
			// the Core could reach it (what the source's client below never asks, then, is not for the policy).
			expect(refusals).toHaveLength(1);
			expect(refusals?.[0]?.where).toMatch(/^promises\.required/);
			expect(refusals?.[0]?.reason).toContain(
				"clients.registered.0.sections.client-assertion.jwks-uri",
			);
		},
		readyWithinMs + 10_000,
	);

	describe("a registered client naming one, claim 2 not required", () => {
		let w: World;
		beforeAll(async () => {
			w = await world([], {
				clients: [await uriMachine(registeredMachine.id, url)],
				released: [promiseNames.clientToken],
				outbound: reaching(),
			});
		}, readyWithinMs + 10_000);
		afterAll(async () => {
			await w?.stop();
		});

		it("its assertion, verified by the key fetched, issues no client_credentials token: only a key written in the record does", async () => {
			const front = await w.front();
			const before = fetched;
			const asked = await front.post(registeredMachine.request("read", api));
			const answered = await front.post(registeredMachine.request("read", api, asked.dpopNonce));
			expect(answered).toMatchObject({
				status: 400,
				body: {
					error: "unauthorized_client",
					error_description:
						"the client authenticates by private_key_jwt under a key written in its record alone",
				},
			});
			// The key set was fetched from the URL: this Core reaches it, and verified the assertion by it.
			expect(fetched).toBeGreaterThan(before);
		});
	});

	describe("a source's client naming one", () => {
		let w: World;
		beforeAll(async () => {
			w = await world([], {
				signedClients: [
					await signedUriMachine(machine.id, url, [{ audience: api, scopes: ["read"] }]),
					await signedMachine(inline.id, inline.publicKey, [{ audience: api, scopes: ["read"] }]),
				],
				outbound: reaching(),
			});
		}, readyWithinMs + 10_000);
		afterAll(async () => {
			await w?.stop();
		});

		it("has no key: its assertion, by the key at the URL, is no authentication, and nothing is fetched", async () => {
			const front = await w.front();
			const before = fetched;
			const asked = await front.post(machine.request("read", api));
			const answered = await front.post(machine.request("read", api, asked.dpopNonce));
			expect(answered).toMatchObject({ status: 401, body: { error: "invalid_client" } });
			const refused = await w.core.lineWhere((line) => line.event === "client-assertion.refused");
			expect(refused.fields).toMatchObject({ client: machine.id, reason: "no key fits" });
			// The same outbound lets a Core reach the URL (above), and this one never asked it.
			expect(fetched).toBe(before);
			// The control: the same key, written in a source's record, authenticates and is issued a token.
			const own = await w.front();
			const nonce = (await own.post(inline.request("read", api))).dpopNonce;
			expect((await own.post(inline.request("read", api, nonce))).status).toBe(200);
		});
	});
});
