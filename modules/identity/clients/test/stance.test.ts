import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { type Stance, stances } from "@mod/promises";
import secretHashModule from "@mod/secret-hash/module";
import { testScryptHash } from "@mod/secret-hash/testing";
import { expect, it } from "vitest";
import { type AuthMethod, authMethods } from "../src/contract.ts";
import clientsModule from "../src/module.ts";

const seen = contract<readonly Stance[]>("test.stances");
const probe = defineModule({ name: "probe", replicaSafe: true, takes: [stances] }, (m) => [
	m.provide(seen).by((c) => c.collect(stances)),
]);
const stanceOf = async (registered: unknown[], extra: readonly Module[] = []) => {
	const app = await assemble({
		modules: [clientsModule, secretHashModule, probe, ...extra],
		config: { ...kernelConfig(), clients: { registered } },
	});
	return app.get(seen).filter((s) => s.promise === "front-compromise-client-token");
};
const shared = (id: string) => ({
	id,
	kind: "confidential",
	method: "client_secret_basic",
	sections: { "client-secret": { hash: testScryptHash("s3cret") } },
});
const pub = { id: "pub", kind: "public", method: "none" };
/** A contributed method, declaring a key held or not. */
const method = (name: string, parts: Partial<AuthMethod> = {}) =>
	defineModule({ name: `method-${name}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(authMethods).by(() => ({
			name,
			signingAlgorithms: ["ES256"],
			claimed: () => undefined,
			verify: async () => undefined,
			...parts,
		})),
	]);

it("holds the client token's promise where no registered client authenticates by a shared secret and every contributed method holds a key, a public one included", async () => {
	for (const registered of [[], [pub]])
		expect(await stanceOf(registered)).toEqual([
			expect.objectContaining({ holds: true, by: "clients" }),
		]);
	expect(await stanceOf([pub], [method("keyed", { keyHeld: true })])).toEqual([
		expect.objectContaining({ holds: true, by: "clients" }),
	]);
});

it("breaks it where a registered client authenticates by a shared secret, naming the first such client's method by its place", async () => {
	const [stance] = await stanceOf([pub, shared("c1"), shared("c2")]);
	expect(stance).toEqual(
		expect.objectContaining({
			holds: false,
			by: "clients",
			setting: "clients.registered.1.method",
		}),
	);
	expect(JSON.stringify(stance)).not.toMatch(/c1|s3cret|scrypt/);
});

it("breaks it where a contributed method declares no key held, naming the method: a source's client may use it", async () => {
	const [stance] = await stanceOf(
		[pub],
		[method("client_secret_jwt", { signingAlgorithms: ["HS256"] })],
	);
	expect(stance).toEqual(expect.objectContaining({ holds: false, by: "clients" }));
	expect(stance?.setting).toBeUndefined();
	expect(stance?.reason).toMatch(/client_secret_jwt/);
});
