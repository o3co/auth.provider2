import type { Client } from "@mod/clients";
import { clients } from "@mod/clients";
import { issuer } from "@mod/issuer";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { passkeys } from "@mod/passkeys";
import { type Guarantee, type Store, spaces, store } from "@mod/store";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { transparencyLog } from "@mod/transparency";
import { clientRecords, logStore } from "@mod/transparency-local";
import transparencyLocal from "@mod/transparency-local/module";
import { opIds } from "@mod/transparency-wire";
import webauthnModule from "@mod/webauthn/module";
import { testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const all: Guarantee[] = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
	"authenticated",
];
const config = (settings = { "accept-unauthenticated": true }) => ({
	...kernelConfig(),
	...storeConfig(settings),
});
/** A signed client of version 3, its one key and its own ceiling: `read` at the API. */
const svc: Client = {
	id: "svc",
	kind: "confidential",
	method: "private_key_jwt",
	registered: false,
	version: 3,
	signed: true,
	section: <T>(s: { readonly name: string }) =>
		(s.name === "client-assertion"
			? { keys: [{ kty: "EC", kid: "k" }], "accept-loose-audience": false }
			: {
					grants: ["client_credentials"],
					scopes: [],
					audiences: [],
					self: [{ audience: "https://api.example", scopes: ["read"] }],
				}) as T,
};
/** The clients and the issuer the wiring reads a client's record by. */
const beside = defineModule({ name: "beside", replicaSafe: true, takes: [] }, (m) => [
	m
		.provide(clients)
		.by(() => ({ find: async (id: string) => (id === svc.id ? svc : undefined) }) as never),
	m
		.provide(issuer)
		.by(() => ({ url: "https://core.example", endpointOrigin: "https://core.example" })),
]);
const refusal = (error: unknown) =>
	BootRefused.is(error)
		? error.refusals.map((r) => `${r.where}: ${r.reason}`).join("\n")
		: String(error);

describe("transparency-local-store", () => {
	it("declares the log's space with a guarantee for each need transparency-local states", async () => {
		const simulated = simulatedStore();
		await assemble({
			modules: [simulated.module, wiring, beside],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		const declared = simulated.declaredSpace("transparency-local-store.log");
		expect([...declared.guarantees].sort()).toEqual([...all].sort());
		expect(declared.subjectData).toBe("retained");
	});

	it("gives transparency-local each client's record as clients holds it: version, signed, keys and its own ceiling", async () => {
		const app = await assemble({
			modules: [storeModule, wiring, beside],
			config: config(),
			runtime: quietRuntime(),
		});
		const records = await app.get(clientRecords);
		const read = await records.find("svc");
		if (!read) throw new Error("no client");
		expect([records.version(read), records.signed(read)]).toEqual([3, true]);
		expect(records.keys(read)).toEqual([{ kty: "EC", kid: "k" }]);
		expect(records.ceiling(read, "https://api.example", "read")).toBe(true);
		expect(records.ceiling(read, "https://api.example", "write")).toBe(false);
		expect(records.ceiling(read, "https://core.example", "read")).toBe(false);
		expect(await records.find("other")).toBeUndefined();
	});

	it("writes the records read as one, held to every version read, and reads them back", async () => {
		const app = await assemble({
			modules: [storeModule, wiring, beside],
			config: config(),
			runtime: quietRuntime(),
		});
		const log = await app.get(logStore);
		const stale = await log.read(["a", "b"]);
		const fresh = await log.read(["a", "b"]);
		expect(fresh.values).toEqual([undefined, undefined]);
		expect(await log.write(fresh, [{ a: 1 }, undefined], fresh.now + 10_000)).toBe("written");
		expect(await log.write(stale, [undefined, { b: 1 }], stale.now + 10_000)).toBe("moved");
		expect((await log.read(["a", "b"])).values).toEqual([{ a: 1 }, undefined]);
		const late = await log.read(["b"]);
		expect(await log.write(late, [{ b: 1 }], late.now - 1)).toBe("late");
	});

	it("boots over a store that does not tell an outside write apart only as the store's setting accepts", async () => {
		const refused = await assemble({
			modules: [storeModule, wiring, beside],
			config: config({ "accept-unauthenticated": false }),
			runtime: quietRuntime(),
		}).catch(refusal);
		expect(refused).toMatch(/store\.accept-unauthenticated: .*transparency-local-store\.log/);
	});

	it("refuses to boot over a store that writes no records of two partitions as one", async () => {
		const lacking = defineModule({ name: "store", replicaSafe: true, takes: [spaces] }, (m) => [
			m.provide(store).by(async (c) => {
				await c.collect(spaces);
				return { get: async () => ({ entry: null, now: 0 }) } as unknown as Store;
			}),
		]);
		const refused = await assemble({
			modules: [lacking, wiring, beside],
			config: kernelConfig(),
			runtime: quietRuntime(),
		})
			.then(() => "booted")
			.catch(refusal);
		expect(refused).toMatch(
			/transparency-local-store: its store writes no records of two partitions as one/,
		);
	});

	it("holds transparency-local's log: a flow's records placed, counted and read back", async () => {
		const held = defineModule({ name: "passkeys", replicaSafe: true, takes: [] }, (m) => [
			m.provide(passkeys).by(() => ({
				assert: async () => ({ kind: "refused", reason: "unknown-credential" }) as const,
				publicKeyOf: async () => undefined,
				settle: async () => false,
			})),
		]);
		const app = await assemble({
			modules: [
				storeModule,
				wiring,
				beside,
				keysModule,
				testHolder(),
				webauthnModule,
				held,
				transparencyLocal,
			],
			config: {
				...config(),
				...keysConfig(),
				...webauthnConfig(),
				"transparency-local": { origin: testOrigin },
			},
			runtime: quietRuntime(),
		});
		const log = await app.get(transparencyLog);
		const flow = { of: "subject", id: "s1" } as const;
		const answer = await log.append(
			{
				kind: "abandonment",
				flow,
				op: opIds.abandonment("o1", 1),
				stage: 1,
				last: true,
				abandons: { op: "o1", attempt: 1, digest: "d".repeat(43) },
				preimage: { v: 1, evidence: [], content: {} },
			},
			0,
		);
		expect(answer).toMatchObject({ result: "accepted", position: 1 });
		expect(await log.head(flow)).toBe(1);
		expect(await log.of(flow, "o1")).toEqual({ stages: 0, last: false, abandonments: 1 });
		expect((await log.at(flow, 1))?.finding).toEqual({ verdict: "verified", outcome: "took" });
	});
});
