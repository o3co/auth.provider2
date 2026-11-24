import { assemble } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { bothOf, composedConfig, composedModules } from "../../../test/composed.ts";
import type { AccessGrant } from "../../contract.ts";
import { tokensConfig } from "../../testing.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });
const grant: AccessGrant = {
	subject: "s",
	subjectKind: "user",
	issuedTo: "c",
	audience: ["api"],
	scope: [],
};
const boot = async () =>
	bothOf(
		await assemble({
			modules: composedModules,
			config: { ...composedConfig(), ...tokensConfig() },
			runtime,
		}),
	);

describe("the time an issuance was accepted", () => {
	it("takes the time its issuance was accepted as the token's iat, its lifetime running from there", async () => {
		const t = await boot();
		const acceptedAt = now - 30_500;
		const prepared = await t.prepare({ grant, grantType: "test" }, { acceptedAt });
		if (prepared.kind !== "prepared") throw new Error(prepared.policy);
		const claims = JSON.parse(prepared.claimsText);
		expect(claims.iat).toBe(Math.floor(acceptedAt / 1000));
		expect(claims.exp - claims.iat).toBe(300);
		const issued = await t.sign(prepared);
		expect(issued).toMatchObject({ kind: "issued", access: { expiresIn: 269 } });
		for (const wrong of [Number.NaN, -1, 1.5]) {
			await expect(t.prepare({ grant, grantType: "test" }, { acceptedAt: wrong })).rejects.toThrow(
				RangeError,
			);
		}
	});

	it("refuses at sign, once prepared, only a token with less than a second left", async () => {
		const t = await boot();
		const prepared = await t.prepare({ grant, grantType: "test" }, { acceptedAt: now - 299_500 });
		if (prepared.kind !== "prepared") throw new Error(prepared.policy);
		expect(await t.sign(prepared)).toMatchObject({ kind: "refused", reason: "no_lifetime_left" });
	});
});
