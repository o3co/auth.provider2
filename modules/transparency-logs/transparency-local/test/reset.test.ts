import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { instructionLimit } from "@mod/reset-wire";
import type { ResetAnswer } from "@mod/transparency";
import { logTyps } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { boot, subjectFlow, testClock } from "./fixtures/world.ts";

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** An embedder's recovery service's ES256 key: its public JWK (with kid) and a signer of instructions. */
function recoveryKey(kid = "reset-1") {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid, alg: "ES256" };
	const privateJwk = { ...pair.privateKey.export({ format: "jwk" }), kid, alg: "ES256" };
	const signedText = (text: string, typ: string = logTyps.resetInstruction) => {
		const input = `${b64({ alg: "ES256", typ, kid })}.${Buffer.from(text).toString("base64url")}`;
		const signature = sign("sha256", Buffer.from(input), {
			key: pair.privateKey,
			dsaEncoding: "ieee-p1363",
		});
		return `${input}.${signature.toString("base64url")}`;
	};
	const signed = (payload: unknown, typ?: string) => signedText(JSON.stringify(payload), typ);
	/** The payload signed with spaces after it, the whole instruction exactly `length` bytes. */
	const paddedTo = (length: number, payload: unknown) => {
		for (let n = 0; n < length; n++) {
			const text = signedText(`${JSON.stringify(payload)}${" ".repeat(n)}`);
			if (text.length === length) return text;
			if (text.length > length) break;
		}
		throw new Error(`no padding makes an instruction of ${length} bytes`);
	};
	return { jwk, privateJwk, signed, paddedTo };
}

const instructionFor = (subject: string, nowMs: number, over: Record<string, unknown> = {}) => ({
	v: 1,
	installation: "inst-1",
	subject,
	action: "reset",
	kg: 0,
	id: randomBytes(16).toString("base64url"),
	iat: Math.floor(nowMs / 1000),
	exp: Math.floor(nowMs / 1000) + 600,
	...over,
});

async function world() {
	const clock = testClock();
	const key = recoveryKey();
	const w = await boot({
		clock,
		section: { installation: "inst-1", "reset-keys": [{ version: 1, keys: [key.jwk] }] },
	});
	const reset = (instruction: string): Promise<ResetAnswer> => {
		return w.log.reset(instruction);
	};
	return { ...w, clock, key, reset };
}

describe("a reset placed by the log in the Core (L0)", () => {
	it("places a reset boundary at the subject's head, judged as the monitor would, and the key generation moves on", async () => {
		const w = await world();
		const flow = subjectFlow();
		const answer = await w.reset(w.key.signed(instructionFor(flow.id, w.clock.now())));
		expect(answer).toMatchObject({ result: "accepted", position: 1 });
		const placed = await w.log.at(flow, 1);
		expect(placed?.record).toMatchObject({
			kind: "resetBoundary",
			writer: { role: "monitor" },
			stage: 1,
			last: true,
		});
		expect(placed?.finding).toEqual({ verdict: "verified", outcome: "took" });
	});

	it("answers the same instruction sent again as placed, and another under its id a conflict", async () => {
		const w = await world();
		const flow = subjectFlow();
		const instruction = instructionFor(flow.id, w.clock.now());
		const first = await w.reset(w.key.signed(instruction));
		expect(await w.reset(w.key.signed(instruction))).toEqual(first);
		expect(await w.reset(w.key.signed({ ...instruction, exp: instruction.exp - 1 }))).toEqual({
			v: 1,
			result: "conflict",
		});
		expect(await w.log.head(flow)).toBe(1);
	});

	it("places nothing for an instruction of no shape, another key, installation or key generation, or one outside its window", async () => {
		const w = await world();
		const flow = subjectFlow();
		const now = w.clock.now();
		const stranger = recoveryKey("reset-1");
		for (const [instruction, fault] of [
			["a.b.c", "shape"],
			[stranger.signed(instructionFor(flow.id, now)), "signature"],
			[w.key.signed(instructionFor(flow.id, now), "jwt"), "signature"],
			[w.key.signed(instructionFor(flow.id, now, { installation: "inst-2" })), "installation"],
			[w.key.signed(instructionFor(flow.id, now, { kg: 1 })), "generation"],
			[w.key.signed(instructionFor(flow.id, now - 3_600_000)), "time"],
		] as const)
			expect(await w.reset(instruction), fault).toEqual({ v: 1, result: "invalid", fault });
		expect(await w.log.head(flow)).toBe(0);
	});

	it("refuses an instruction longer than reset-wire's limit as shape, before it is read, a placed one padded and sent again among them", async () => {
		const w = await world();
		const flow = subjectFlow();
		const instruction = instructionFor(flow.id, w.clock.now());
		const atLimit = w.key.paddedTo(instructionLimit, instruction);
		expect(await w.reset(atLimit)).toMatchObject({ result: "accepted", position: 1 });
		const shape = { v: 1, result: "invalid", fault: "shape" };
		expect(await w.reset(w.key.paddedTo(instructionLimit + 1, instruction))).toEqual(shape);
		const other = instructionFor(flow.id, w.clock.now());
		expect(await w.reset(w.key.paddedTo(instructionLimit + 1, other))).toEqual(shape);
		expect(await w.log.head(flow)).toBe(1);
	});

	it("answers a placed reset sent again by the set it was placed under, after a newer one, and refuses the same payload another key signed", async () => {
		const clock = testClock();
		const old = recoveryKey("reset-1");
		const fresh = recoveryKey("reset-2");
		const flow = subjectFlow();
		const instruction = instructionFor(flow.id, clock.now());
		const first = await boot({
			clock,
			section: { installation: "inst-1", "reset-keys": [{ version: 1, keys: [old.jwk] }] },
		});
		const placed = await first.log.reset(old.signed(instruction));
		expect(placed).toMatchObject({ result: "accepted" });
		expect(await first.log.reset(fresh.signed(instruction))).toEqual({
			v: 1,
			result: "conflict",
		});
		expect(await first.log.reset(old.signed(instruction, "jwt"))).toEqual({
			v: 1,
			result: "conflict",
		});
	});

	it("answers every reset of a readable shape invalid, its installation, where no installation is set", async () => {
		const w = await boot();
		const key = recoveryKey();
		expect(await w.log.reset(key.signed(instructionFor("sub-1", Date.now())))).toEqual({
			v: 1,
			result: "invalid",
			fault: "installation",
		});
		// Its shape is read first: one that does not read is `shape`, installation or none.
		expect(await w.log.reset("a.b.c")).toEqual({ v: 1, result: "invalid", fault: "shape" });
	});

	it("refuses to boot with a reset key that is no public key, one named twice in a version, or one of the Core ring", async () => {
		const key = recoveryKey();
		const ring = (await boot()).keys;
		const ringKey = ring.coreRing(ring.generation())?.[0];
		for (const [keys, reason] of [
			[[{ kty: "EC" }], "version 1: a key that is no public key"],
			[[key.privateJwk], "version 1: a key that is no public key"],
			[[{ ...key.jwk, kid: undefined }], "version 1: a key with no kid of its own"],
			[
				[key.jwk, { ...recoveryKey().jwk, kid: key.jwk.kid }],
				"version 1: a key with no kid of its own",
			],
			[[key.jwk, { ...key.jwk, kid: "reset-2" }], "version 1: a key named twice"],
			[[ringKey], "version 1: a key of the Core ring"],
		] as const)
			await expect(
				boot({ section: { installation: "inst-1", "reset-keys": [{ version: 1, keys }] } }),
				reason,
			).rejects.toMatchObject({ refusals: [{ where: "transparency-local.reset-keys", reason }] });
	});
});
