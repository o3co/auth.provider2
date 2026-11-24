import { assemble } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import { describe, expect, it } from "vitest";
import {
	bothOf,
	composedConfig,
	composedModules,
	issueFor,
	signAccess,
} from "../../../test/composed.ts";
import { type AccessGrant, accessTokenClaims } from "../../contract.ts";
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
const claimsOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

async function boot() {
	const app = await assemble({
		modules: composedModules,
		config: { ...composedConfig(), ...tokensConfig() },
		runtime,
	});
	return { t: bothOf(app), signer: app.get(accessTokenSigning) };
}

describe("the claims tokens writes, closed", () => {
	it("holds each in the table, by how it is held to account", async () => {
		const { t } = await boot();
		const full = {
			...grant,
			actor: { subject: "a" },
			amr: ["hwk"],
			authenticatedAt: now,
			acr: "a",
			standingAt: now,
		};
		const issued = await issueFor(t, full, {
			binding: { member: "jkt", confirmation: "x", tokenType: "DPoP" },
		});
		const written = Object.keys(claimsOf(issued.token));
		for (const name of written) expect(Object.hasOwn(accessTokenClaims, name), name).toBe(true);
		expect(Object.isFrozen(accessTokenClaims)).toBe(true);
		expect(accessTokenClaims).toMatchObject({
			sub: "evidence",
			client_id: "evidence",
			cnf: "evidence",
			o3co_subject_kind: "derived",
			txr: "outside",
		});
	});

	it("writes the subject's kind the grant says, and reads it back", async () => {
		const { t } = await boot();
		const client = { ...grant, subject: "c", subjectKind: "client" as const };
		for (const given of [grant, client]) {
			const issued = await issueFor(t, given);
			expect(claimsOf(issued.token).o3co_subject_kind).toBe(given.subjectKind);
			const read = await t.verifyAccess(issued.token);
			expect(read.kind === "valid" && read.grant.subjectKind).toBe(given.subjectKind);
		}
	});

	it("refuses as shape a token without a subject kind, with another, a client's for another subject, or holding a receipt claim", async () => {
		const { t, signer } = await boot();
		const claims = claimsOf((await issueFor(t, grant)).token);
		const { o3co_subject_kind: _, ...without } = claims;
		for (const forged of [
			without,
			{ ...claims, o3co_subject_kind: "service" },
			{ ...claims, o3co_subject_kind: "client" },
			{ ...claims, txr: "receipt" },
		]) {
			expect(
				await t.verifyAccess(await signAccess(signer, forged)),
				JSON.stringify(forged),
			).toEqual({ kind: "invalid", reason: "shape" });
		}
		expect((await t.verifyAccess(await signAccess(signer, claims))).kind).toBe("valid");
	});
});

it("writes the actor chain as act, and amr, auth_time and acr, only when the grant gives them", async () => {
	const { t } = await boot();
	const plain = claimsOf((await issueFor(t, { ...grant, amr: [] })).token);
	expect(["act", "amr", "auth_time", "acr"].filter((name) => name in plain)).toEqual([]);
	const issued = await issueFor(t, {
		...grant,
		actor: { subject: "a", actor: { subject: "b" } },
		amr: ["hwk", "pwd"],
		authenticatedAt: now - 1_500,
	});
	const claims = claimsOf(issued.token);
	expect(claims.act).toEqual({ sub: "a", act: { sub: "b" } });
	expect(claims.amr).toEqual(["hwk", "pwd"]);
	expect(claims.auth_time).toBe(Math.floor((now - 1_500) / 1000));
	const checked = await t.verifyAccess(issued.token);
	expect(checked.kind === "valid" && checked.grant).toEqual({
		...grant,
		actor: { subject: "a", actor: { subject: "b" } },
		amr: ["hwk", "pwd"],
		authenticatedAt: Math.floor((now - 1_500) / 1000) * 1000,
	});
});

it("writes no auth_time for a grant whose authentication time is not known, whatever time it holds", async () => {
	const { t } = await boot();
	const issued = await issueFor(t, {
		...grant,
		authenticatedAt: now - 1_500,
		authenticatedAtUnknown: true,
	});
	expect("auth_time" in claimsOf(issued.token)).toBe(false);
	const checked = await t.verifyAccess(issued.token);
	expect(checked.kind === "valid" && checked.grant.authenticatedAt).toBeUndefined();
});
