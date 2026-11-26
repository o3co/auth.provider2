import { createHash } from "node:crypto";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { expect, it } from "vitest";
import {
	type EvidenceAnswer,
	type FirstKeyEvidence,
	type FirstKeyStart,
	firstKeyEvidence,
	type StartOutcome,
} from "../src/contract.ts";

const seen = contract<readonly FirstKeyEvidence[]>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [firstKeyEvidence] },
	(m) => [m.provide(seen).by((c) => c.collect(firstKeyEvidence))],
);
const contributing = (name: string, evidence: FirstKeyEvidence) =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(firstKeyEvidence).by(() => evidence),
	]);
const said = (kind: EvidenceAnswer["kind"]): EvidenceAnswer => ({ kind });
const digest = (text: string) => createHash("sha256").update(text).digest("base64url");
const fields = (items: unknown) => (items ?? {}) as Record<string, unknown>;

/**
 * The four kinds the design names, each a stand-in on the one contract, holding its own record:
 * alice holds every kind, bob a password only, and dan a code whose record is lost.
 */
function standIns(told: StartOutcome[]) {
	const passwords = new Map([
		["alice", "pass"],
		["bob", "word"],
	]);
	// The record says who holds none; one it no longer has, it cannot say holds none.
	const lastWindow = new Map<string, number | "none">([
		["alice", 0],
		["bob", "none"],
	]);
	const keys = new Map([["alice", "key-1"]]);
	const moved = new Map([["https://old.example sub-a", "alice"]]);
	const password: FirstKeyEvidence = {
		kind: "password",
		check: async (_, subject, items) => {
			// Users' verify does its waits and the same work for a subject of none.
			const held = subject && passwords.get(subject);
			if (!held) return said(subject ? "absent" : "failed");
			return said(fields(items).password === held ? "passed" : "failed");
		},
		settled: async (_, __, outcome) => {
			told.push(outcome);
		},
	};
	const totp: FirstKeyEvidence = {
		kind: "totp",
		check: async (_, subject, items) => {
			const last = subject === undefined ? undefined : lastWindow.get(subject);
			if (last === "none") return said("absent");
			if (last === undefined) return said("failed");
			const { code, window } = fields(items);
			if (typeof window !== "number" || window <= last || code !== `code-${window}`)
				return said("failed");
			lastWindow.set(subject as string, window);
			return said("passed");
		},
	};
	const securityKey: FirstKeyEvidence = {
		kind: "security-key",
		// The challenge comes from the nonce, so nothing is kept between; a decoy stands for no key.
		prepare: async (start, subject) => ({
			challenge: digest(start.nonce),
			allow: [(subject && keys.get(subject)) || digest(`decoy ${start.identifier}`)],
		}),
		check: async (start, subject, items) => {
			const held = subject && keys.get(subject);
			if (!held) return said(subject ? "absent" : "failed");
			const { credential, challenge } = fields(items);
			return said(credential === held && challenge === digest(start.nonce) ? "passed" : "failed");
		},
	};
	const formerIdp: FirstKeyEvidence = {
		kind: "former-idp",
		prepare: async (start) => ({ nonce: start.nonce }),
		check: async (start, subject, items) => {
			if (!subject) return said("failed");
			const { iss, sub, nonce } = fields(items);
			const mapped = [...moved.values()].includes(subject);
			if (!mapped) return said("absent");
			const named = moved.get(`${iss} ${sub}`) === subject;
			return said(named && nonce === start.nonce ? "passed" : "failed");
		},
	};
	return [password, totp, securityKey, formerIdp];
}

/** A stand-in for the path: every kind asked once, a fault among them too, then each told the start's end. */
async function asked(
	kinds: readonly FirstKeyEvidence[],
	start: FirstKeyStart,
	subject: string | undefined,
	request: Readonly<Record<string, unknown>>,
) {
	const answers: Record<string, EvidenceAnswer["kind"] | "unavailable"> = {};
	for (const k of kinds) {
		try {
			answers[k.kind] = (await k.check(start, subject, request[k.kind])).kind;
		} catch (error) {
			if (!(error instanceof Unavailable)) throw error;
			answers[k.kind] = "unavailable";
		}
	}
	const all = Object.values(answers);
	const passed = all.every((a) => a === "passed" || a === "absent") && all.includes("passed");
	const outcome: StartOutcome = all.includes("unavailable")
		? "unavailable"
		: passed
			? "passed"
			: "failed";
	for (const k of kinds) await k.settled?.(start, subject, outcome);
	return { answers, outcome };
}

const right = (start: FirstKeyStart, window: number) => ({
	password: { password: "pass" },
	totp: { code: `code-${window}`, window },
	"security-key": { credential: "key-1", challenge: digest(start.nonce) },
	"former-idp": { iss: "https://old.example", sub: "sub-a", nonce: start.nonce },
});

it("takes each kind of a first key's evidence once by its name: a password, a one-time code, a security key, a former IdP", async () => {
	const kinds = standIns([]);
	const app = await assemble({
		modules: [collecting, ...kinds.map((k) => contributing(k.kind, k))],
		config: kernelConfig(),
	});
	expect(app.get(seen).map((e) => e.kind)).toEqual(kinds.map((k) => k.kind));
});

it("answers passed, failed, or absent where the kind's record holds none, and fails a subject of none", async () => {
	const kinds = standIns([]);
	const start = { nonce: "n1", identifier: "alice" };
	expect((await asked(kinds, start, "alice", right(start, 1))).answers).toEqual({
		password: "passed",
		totp: "passed",
		"security-key": "passed",
		"former-idp": "passed",
	});
	// The window taken is refused again; the ID token's nonce is the start's.
	const again = { nonce: "n2", identifier: "alice" };
	const replayed = { ...right(again, 1), "former-idp": right(start, 1)["former-idp"] };
	expect((await asked(kinds, again, "alice", replayed)).answers).toMatchObject({
		totp: "failed",
		"former-idp": "failed",
	});
	const bob = { nonce: "n3", identifier: "bob" };
	expect((await asked(kinds, bob, "bob", { password: { password: "word" } })).answers).toEqual({
		password: "passed",
		totp: "absent",
		"security-key": "absent",
		"former-idp": "absent",
	});
	// A record lost fails: only the record's word that none is held is absent.
	const dan = { nonce: "n5", identifier: "dan" };
	expect((await asked(kinds, dan, "dan", {})).answers.totp).toBe("failed");
	const none = { nonce: "n4", identifier: "carol" };
	const answers = Object.values((await asked(kinds, none, undefined, right(none, 2))).answers);
	expect(answers).toEqual(["failed", "failed", "failed", "failed"]);
});

it("prepares alike, in shape, for a subject holding the kind, one holding none, and none", async () => {
	const [, , securityKey] = standIns([]);
	const start = { nonce: "n", identifier: "someone" };
	const shapes = await Promise.all(
		["alice", "bob", undefined].map(async (subject) => securityKey?.prepare?.(start, subject)),
	);
	for (const shape of shapes) {
		expect(shape).toEqual({ challenge: digest("n"), allow: [expect.any(String)] });
	}
	// For one identifier, the decoy each time is the same.
	expect(shapes[1]).toEqual(await securityKey?.prepare?.(start, undefined));
});

it("tells each kind once how the start ended over all kinds, a password passed or not, a fault first", async () => {
	const told: StartOutcome[] = [];
	const kinds = standIns(told);
	const checked: string[] = [];
	const counting = kinds.map((k) => ({
		...k,
		check: async (...args: Parameters<FirstKeyEvidence["check"]>) => {
			checked.push(k.kind);
			return k.check(...args);
		},
	}));
	const start = { nonce: "n", identifier: "alice" };
	await asked(counting, start, "alice", { ...right(start, 1), totp: { code: "wrong", window: 2 } });
	const faulty: FirstKeyEvidence = {
		kind: "faulty",
		check: async () => {
			throw new Unavailable("store");
		},
	};
	checked.length = 0;
	await asked([faulty, ...counting], start, "alice", right(start, 3));
	expect(told).toEqual(["failed", "unavailable"]);
	// The kinds after the fault were checked before any was told.
	expect(checked).toEqual(counting.map((k) => k.kind));
});

it("refuses boot for two kinds of one name", async () => {
	const [password] = standIns([]) as [FirstKeyEvidence];
	const twice = assemble({
		modules: [collecting, contributing("one", password), contributing("other", password)],
		config: kernelConfig(),
	});
	await expect(twice).rejects.toBeInstanceOf(BootRefused);
});
