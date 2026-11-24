import { addedClaimsLimits, addedClaimsWith } from "@mod/added-claims";
import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { checkClaims } from "../../claims/claims.ts";
import type { IssuancePolicy, IssuanceRequest } from "../../contract.ts";
import { section } from "../../section.ts";
import { issuing, judging, type MadeAccess } from "../issuance.ts";

const request = {
	grant: {
		subject: "s",
		subjectKind: "user" as const,
		issuedTo: "c",
		audience: ["api"],
		scope: [],
	},
	grantType: "test",
} as const;

/** A deadline the test fires itself, so no load on the machine moves it. */
const deadlineFired = () => {
	const deadline = new AbortController();
	return { deadline, of: () => deadline.signal };
};

it("answers unavailable once the policies' deadline passes, aborting the policy's signal, and allows nothing", async () => {
	const seen: AbortSignal[] = [];
	const hanging: IssuancePolicy = {
		name: "hanging",
		judge: (_request, signal) => {
			if (signal) seen.push(signal);
			return new Promise(() => {});
		},
	};
	const { deadline, of } = deadlineFired();
	const judged = judging([hanging], () => 0, of)(request);
	deadline.abort();
	await expect(judged).rejects.toSatisfy(isUnavailable);
	expect(seen.map((signal) => signal.aborted)).toEqual([true]);
});

it("holds one deadline over every policy together, asking none once it passed", async () => {
	const asked: string[] = [];
	const { deadline, of } = deadlineFired();
	const first: IssuancePolicy = {
		name: "a",
		judge: async () => {
			asked.push("a");
			deadline.abort();
			return { kind: "allowed" };
		},
	};
	const second: IssuancePolicy = {
		name: "b",
		judge: async () => {
			asked.push("b");
			return { kind: "allowed" };
		},
	};
	await expect(judging([second, first], () => 0, of)(request)).rejects.toSatisfy(isUnavailable);
	expect(asked).toEqual(["a"]);
});

it("judges as before within the deadline", async () => {
	const allowing: IssuancePolicy = { name: "a", judge: async () => ({ kind: "allowed" }) };
	expect(await judging([allowing], () => 0, deadlineFired().of)(request)).toEqual({
		kind: "allowed",
	});
});

it("takes the policies' deadline written with its unit, from 1s to 1m, 10s unless set", () => {
	const parsed = (value?: string) =>
		section.safeParse({ revocation: "denylist", ...(value ? { "issuance-timeout": value } : {}) });
	expect(parsed().data?.["issuance-timeout"]).toBe(10_000);
	expect(["1s", "1m", "2500ms"].map((value) => parsed(value).data?.["issuance-timeout"])).toEqual([
		1000, 60_000, 2500,
	]);
	expect(["999ms", "61s", "10"].map((value) => parsed(value).success)).toEqual([
		false,
		false,
		false,
	]);
});

describe("the claims a grant adds, as issuing reads them", () => {
	const seen: IssuanceRequest[] = [];
	const judge = async (asked: IssuanceRequest) => {
		seen.push(asked);
		return { kind: "allowed" } as const;
	};
	const make = (): MadeAccess => {
		throw new Error("not issued here");
	};
	const { admits, issue } = issuing(
		judge,
		make,
		() => 0,
		addedClaimsWith(addedClaimsLimits.parse({})).of,
	);
	const grant = request.grant;

	it("refuses a null as a TypeError naming its path, before any policy runs, at admits as at issue", async () => {
		seen.length = 0;
		const nulled = { grant: { ...grant, claims: { c: { a: null } } }, grantType: "test" };
		for (const asked of [() => issue(nulled), () => admits(nulled)]) {
			await expect(asked()).rejects.toThrow("null at c.a");
		}
		expect(seen).toEqual([]);
	});

	it("shows the policies the claims as copied, frozen, at admits as at issue, an empty set as none", async () => {
		seen.length = 0;
		const claims = { a: [1] };
		expect(await admits({ grant: { ...grant, claims }, grantType: "test" })).toEqual({
			kind: "allowed",
		});
		expect(seen[0]?.grant.claims).toEqual(claims);
		expect(seen[0]?.grant.claims).not.toBe(claims);
		expect(Object.isFrozen(seen[0]?.grant.claims?.a)).toBe(true);
		await admits({ grant: { ...grant, claims: {} }, grantType: "test" });
		expect("claims" in (seen[1]?.grant ?? {})).toBe(false);
		// issue shows them the same copy before it issues.
		await expect(issue({ grant: { ...grant, claims }, grantType: "test" })).rejects.toThrow();
		expect(seen[2]?.grant.claims).toEqual(claims);
		expect(seen[2]?.grant.claims).not.toBe(claims);
		expect(Object.isFrozen(seen[2]?.grant.claims?.a)).toBe(true);
	});
});

describe("the subject's kind and the names tokens writes, as issuing reads them", () => {
	const allowed = async () => ({ kind: "allowed" }) as const;
	const made = { headerText: "{}", claimsText: "{}" };
	const { admits, prepare } = issuing(
		allowed,
		() => ({ ...made, signed: async () => ({ kind: "too-large" }) }),
		() => 0,
		addedClaimsWith(addedClaimsLimits.parse({})).of,
	);
	const asked = (grant: object) => ({ grant: { ...request.grant, ...grant }, grantType: "test" });

	it("refuses a grant saying no subject kind, or a client's token for another subject, at admits as at prepare", async () => {
		for (const grant of [
			{ subjectKind: undefined },
			{ subjectKind: "service" },
			{ subjectKind: "client", subject: "s", issuedTo: "c" },
		]) {
			for (const ask of [admits, prepare]) {
				await expect(ask(asked(grant) as IssuanceRequest), JSON.stringify(grant)).rejects.toThrow(
					TypeError,
				);
			}
		}
		expect(await admits(asked({ subjectKind: "client", subject: "c", issuedTo: "c" }))).toEqual({
			kind: "allowed",
		});
	});

	it("refuses an added claim taking a name tokens writes, by its own table whatever added-claims reserves", async () => {
		for (const name of ["o3co_subject_kind", "txr"]) {
			await expect(admits(asked({ claims: { [name]: "x" } }))).rejects.toThrow(TypeError);
			expect(() => checkClaims(request.grant, { [name]: "x" })).toThrow(
				`a claim tokens writes is added: ${name}`,
			);
		}
	});
});

describe("prepare and sign, as issuing makes them", () => {
	let signings = 0;
	const issuedAccess = {
		token: "t",
		id: "i",
		expiresAt: 60_000,
		expiresIn: 60,
		tokenType: "Bearer",
	};
	const { prepare, sign, issue } = issuing(
		async (r) =>
			r.grantType === "refused"
				? { kind: "refused", policy: "p", reason: "r", description: "d" }
				: { kind: "allowed" },
		() => ({
			headerText: '{"typ":"at+jwt"}',
			claimsText: '{"jti":"i"}',
			signed: async () => {
				signings++;
				return { access: issuedAccess };
			},
		}),
		() => 0,
		addedClaimsWith(addedClaimsLimits.parse({})).of,
	);

	it("prepares the texts as made, signing nothing, then signs them, again where asked", async () => {
		signings = 0;
		const prepared = await prepare(request);
		expect(prepared).toEqual({
			kind: "prepared",
			headerText: '{"typ":"at+jwt"}',
			claimsText: '{"jti":"i"}',
		});
		expect(Object.isFrozen(prepared)).toBe(true);
		expect(signings).toBe(0);
		if (prepared.kind !== "prepared") throw new Error("refused");
		for (const _ of [1, 2]) {
			expect(await sign(prepared)).toEqual({ kind: "issued", access: issuedAccess });
		}
		expect(signings).toBe(2);
		expect(await issue(request)).toEqual({ kind: "issued", access: issuedAccess });
	});

	it("answers a refusal at prepare as issue does, and signs only what it prepared", async () => {
		const refused = { kind: "refused", policy: "p", reason: "r", description: "d" };
		expect(await prepare({ ...request, grantType: "refused" })).toEqual(refused);
		expect(await issue({ ...request, grantType: "refused" })).toEqual(refused);
		const copied = { ...(await prepare(request)) } as Parameters<typeof sign>[0];
		await expect(sign(copied)).rejects.toThrow(TypeError);
	});
});
