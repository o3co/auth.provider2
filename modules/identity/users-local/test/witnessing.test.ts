import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import witnessHttp from "@mod/passkey-witness-http/module";
import { passkeyWitnessHttpConfig } from "@mod/passkey-witness-http/testing";
import witnessingModule from "@mod/passkey-witnessing/module";
import { type PasskeyWitnessing, passkeyWitnessing } from "@mod/passkeys";
import { simulatedStore } from "@mod/store/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { describe, expect, it } from "vitest";
import usersLocal from "../src/module.ts";

const seen = contract<readonly PasskeyWitnessing[]>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [passkeyWitnessing] },
	(m) => [m.provide(seen).by((c) => c.collect(passkeyWitnessing))],
);
const ledger = "127.0.0.1:8443";
const httpConfig = {
	outbound: { allow: ["127.0.0.1"], "plain-loopback": [ledger] },
	...passkeyWitnessHttpConfig({
		"read-url": `http://${ledger}/w/read`,
		"enroll-url": `http://${ledger}/w/enroll`,
		"withdraw-url": `http://${ledger}/w/withdraw`,
	}),
};
const witnesses: Record<string, () => Module[]> = {
	"@mod/users-local": () => [simulatedStore().module, usersLocal],
	"@mod/passkey-witness-http": () => [outboundModule, tlsOptionsForTests, witnessHttp],
};
/** passkey-witnessing over the witness modules given, as combinations brings it with passkeys. */
const boot = (modules: readonly Module[]) =>
	assemble({
		modules: [...modules, witnessingModule, collecting],
		config: {
			...kernelConfig(),
			// The outside ledger's sections only where it is composed.
			...(modules.includes(witnessHttp) ? httpConfig : {}),
		},
		runtime: quietRuntime(),
	});

describe("users-local's witness, with passkey-witnessing", () => {
	it("boots over users-local's witness and over the outside ledger's, each alone", async () => {
		for (const [name, modules] of Object.entries(witnesses)) {
			const app = await boot(modules());
			expect(app.get(seen), name).toHaveLength(1);
			await app.stop();
		}
	});

	it("keeps the marks for key generations in its space, a mark of a generation before replaced", async () => {
		const app = await boot(witnesses["@mod/users-local"]?.() ?? []);
		const [witnessing] = app.get(seen);
		if (!witnessing) throw new Error("no witnessing");
		await witnessing.mark("s", 1);
		await witnessing.withdraw("s", 2);
		expect(await witnessing.marked("s")).toBe(false);
		// A late mark of 1 lands, then 2's: 2's replaces it, and a withdraw below 2 leaves it.
		await witnessing.mark("s", 1);
		await witnessing.mark("s", 2);
		await witnessing.withdraw("s", 2);
		expect(await witnessing.marked("s")).toBe(true);
		await app.stop();
	});

	it("refuses boot with no witness, and with both", async () => {
		const both = Object.values(witnesses).flatMap((modules) => modules());
		for (const modules of [[], both]) {
			const refused = await boot(modules).catch((e: unknown) => e);
			expect(refused).toBeInstanceOf(BootRefused);
			expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["passkey-witnessing"]);
		}
	});
});
