import { type FirstKeyEvidence, firstKeyEvidence } from "@mod/first-key";
import { itemsOf } from "@mod/first-key/testing";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { evidence } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import secretHashModule from "@mod/secret-hash/module";
import type { PartVerification, Users, Verified } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser, usersConfig } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import { passwordEvidence, pendingBound } from "../src/evidence.ts";
import passwordEvidenceModule from "../src/module.ts";

const alice: Verified = { kind: "user", user: { subject: "s-alice", attributes: {} } };
const start = (nonce: string, identifier = "alice") => ({ nonce, identifier });

/** Users answering alice for "pass", recording each check asked and each settling. */
function recording() {
	const asked: string[] = [];
	const settled: [string, boolean][] = [];
	const users: Pick<Users, "verifyAsPart"> = {
		verifyAsPart: async (identifier, password): Promise<PartVerification> => {
			asked.push(`${identifier}:${password}`);
			const verified =
				identifier === "alice" && password === "pass" ? alice : { kind: "none" as const };
			return { verified, settle: (passed) => settled.push([`${identifier}:${password}`, passed]) };
		},
	};
	return { evidence: passwordEvidence(users), asked, settled };
}

describe("passwordEvidence", () => {
	it("passes the password of the subject the identifier names, and fails any other, never answering absent", async () => {
		const { evidence: e } = recording();
		expect(await e.check(start("1"), "s-alice", { password: "pass" })).toEqual({ kind: "passed" });
		expect(await e.check(start("2"), "s-alice", { password: "wrong" })).toEqual({ kind: "failed" });
		// The identifier names another subject than the path's.
		expect(await e.check(start("3"), "s-bob", { password: "pass" })).toEqual({ kind: "failed" });
		expect(await e.check(start("4", "bob"), "s-bob", {})).toEqual({ kind: "failed" });
	});

	it("checks the identifier alike for a subject of none, and any items of another shape as no password", async () => {
		const { evidence: e, asked } = recording();
		expect(await e.check(start("1", "carol"), undefined, { password: "pass" })).toEqual({
			kind: "failed",
		});
		for (const items of [
			undefined,
			null,
			"pass",
			["pass"],
			{ password: 7 },
			Object.create({ password: "pass" }),
		]) {
			expect(await e.check(start("2"), "s-alice", items)).toEqual({ kind: "failed" });
		}
		expect(asked).toEqual(["carol:pass", ...Array.from({ length: 6 }, () => "alice:")]);
	});

	it("reads its items as the path hands them from a start's request: the password sent, or none", async () => {
		const { evidence } = recording();
		const handed = (password?: string) => itemsOf({ password })[evidence.kind];
		expect(await evidence.check(start("n1"), "s-alice", handed("pass"))).toEqual({
			kind: "passed",
		});
		expect(await evidence.check(start("n2"), "s-alice", handed("wrong"))).toEqual({
			kind: "failed",
		});
		expect(await evidence.check(start("n3"), "s-alice", handed())).toEqual({ kind: "failed" });
	});

	it("fails items of another shape even where an empty password is the user's", async () => {
		const users: Pick<Users, "verifyAsPart"> = {
			verifyAsPart: async () => ({ verified: alice, settle: () => {} }),
		};
		const e = passwordEvidence(users);
		for (const items of [undefined, {}, { password: 7 }]) {
			expect(await e.check(start("1"), "s-alice", items)).toEqual({ kind: "failed" });
		}
		expect(await e.check(start("2"), "s-alice", { password: "" })).toEqual({ kind: "passed" });
	});

	it("settles each start's check once, passed only where the start passed", async () => {
		const { evidence: e, settled } = recording();
		for (const nonce of ["a", "b", "c"])
			await e.check(start(nonce), "s-alice", { password: "pass" });
		await e.settled?.(start("a"), "s-alice", "passed");
		await e.settled?.(start("a"), "s-alice", "passed");
		await e.settled?.(start("b"), "s-alice", "failed");
		await e.settled?.(start("c"), "s-alice", "unavailable");
		await e.settled?.(start("unknown"), "s-alice", "passed");
		expect(settled).toEqual([
			["alice:pass", true],
			["alice:pass", false],
			["alice:pass", false],
		]);
	});

	it("takes back no failure of its own where the start passed but this kind did not", async () => {
		const { evidence: e, settled } = recording();
		await e.check(start("1"), "s-bob", { password: "pass" });
		await e.settled?.(start("1"), "s-bob", "passed");
		expect(settled).toEqual([["alice:pass", false]]);
	});

	it("lets the oldest check go, counted failed, past its bound of checks awaiting their end", async () => {
		const { evidence: e, settled } = recording();
		const right = { password: "pass" };
		for (let n = 0; n <= pendingBound; n++) await e.check(start(`${n}`), "s-alice", right);
		await e.settled?.(start("0"), "s-alice", "passed");
		await e.settled?.(start(`${pendingBound}`), "s-alice", "passed");
		expect(settled).toEqual([["alice:pass", true]]);
	});

	it("passes a fault of users on, holding nothing for the start", async () => {
		const e = passwordEvidence({
			verifyAsPart: async () => {
				throw new Unavailable("users");
			},
		});
		await expect(e.check(start("1"), "s-alice", {})).rejects.toThrow(Unavailable);
		await expect(e.settled?.(start("1"), "s-alice", "unavailable")).resolves.toBeUndefined();
	});
});

const seen = contract<readonly FirstKeyEvidence[]>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [firstKeyEvidence] },
	(m) => [m.provide(seen).by((c) => c.collect(firstKeyEvidence))],
);

describe("password-evidence composed", () => {
	const boot = async () =>
		assemble({
			modules: [
				passwordEvidenceModule,
				collecting,
				promisesModule,
				usersModule,
				secretHashModule,
				memoryUsersStores().module,
			],
			config: {
				...kernelConfig(),
				...usersConfig([testUser("alice", "correct horse", { subject: "s-alice" })]),
			},
		});

	it("declares the password kind to promises, its guesses the failed checks users' waits allow on each instance", async () => {
		const app = await boot();
		expect(app.get(evidence).kinds()).toEqual([
			{
				kind: "password",
				by: "password-evidence",
				trusts: ["password"],
				strength: { kind: "guesses", guesses: { count: 37, windowMs: 900_000 } },
			},
		]);
	});

	it("checks a password through users as a first key's evidence, by the same name", async () => {
		const app = await boot();
		const [composed] = app.get(seen);
		expect(composed?.kind).toBe("password");
		const answer = await composed?.check(start("n"), "s-alice", { password: "correct horse" });
		expect(answer).toEqual({ kind: "passed" });
		await composed?.settled?.(start("n"), "s-alice", "passed");
	});
});
