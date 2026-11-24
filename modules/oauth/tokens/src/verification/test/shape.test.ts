import { assemble, defineModule, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import { senderBindings } from "@mod/sender-binding";
import { expect, it } from "vitest";
import {
	bothOf,
	composedConfig,
	composedModules,
	issueFor,
	signAccess,
} from "../../../test/composed.ts";
import type { AccessGrant } from "../../contract.ts";
import { tokensConfig } from "../../testing.ts";

const grant: AccessGrant = {
	subject: "s",
	subjectKind: "user",
	issuedTo: "c",
	audience: ["api"],
	scope: [],
};
const claimsOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

async function assembled(extra: Module[] = []) {
	return assemble({
		modules: [...composedModules, ...extra],
		config: { ...composedConfig(), ...tokensConfig() },
		runtime: quietRuntime(),
	});
}

it("refuses as shape a token whose act, amr or auth_time is malformed", async () => {
	const app = await assembled();
	const t = bothOf(app);
	const issued = await issueFor(t, grant);
	const signer = app.get(accessTokenSigning);
	for (const malformed of [
		{ act: { sub: "a", act: { sub: 1 } } },
		{ act: "a" },
		{ amr: "hwk" },
		{ auth_time: "now" },
		{ acr: 7 },
		{ acr: "" },
	]) {
		const token = await signAccess(signer, { ...claimsOf(issued.token), ...malformed });
		expect(await t.verifyAccess(token), JSON.stringify(malformed)).toEqual({
			kind: "invalid",
			reason: "shape",
		});
	}
});

it("refuses a token another issuer stamped, and one bound by two members", async () => {
	const kinds = defineModule({ name: "two-kinds", replicaSafe: true, takes: [] }, (m) =>
		["one", "two"].map((member) =>
			m.contribute(senderBindings).by(() => ({
				member,
				tokenType: member.toUpperCase(),
				read: async () => ({ kind: "absent" as const }),
			})),
		),
	);
	const app = await assembled([kinds]);
	const t = bothOf(app);
	const signer = app.get(accessTokenSigning);
	const claims = claimsOf((await issueFor(t, grant)).token);
	const signed = (changed: Record<string, unknown>) =>
		signAccess(signer, { ...claims, ...changed });
	expect(await t.verifyAccess(await signed({ iss: "https://other.example" }))).toEqual({
		kind: "invalid",
		reason: "issuer",
	});
	expect(await t.verifyAccess(await signed({ cnf: { one: "a", two: "b" } }))).toEqual({
		kind: "invalid",
		reason: "shape",
	});
	expect((await t.verifyAccess(await signed({ cnf: { two: "b" } }))).kind).toBe("valid");
});
