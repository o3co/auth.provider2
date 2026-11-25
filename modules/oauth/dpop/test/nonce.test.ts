import { randomBytes } from "node:crypto";
import { replies } from "@mod/front-core-wire";
import { expect, it } from "vitest";
import { nonces } from "../src/nonce.ts";

/** A nonce's bucket and its MAC, the last 43 characters. */
const partsOf = (nonce: string) => [nonce.slice(0, -43), nonce.slice(-43)] as const;

it("makes a nonce of one bucket, whatever the clock does between its reads", () => {
	const secret = randomBytes(32);
	// Each read of the clock moves it on a whole bucket: a nonce read twice would mix two buckets.
	let at = 0;
	const issued = nonces(secret, 1000, () => {
		at += 1000;
		return at;
	}).issue();
	const bucket = Number(partsOf(issued)[0]);
	expect(nonces(secret, 1000, () => bucket * 1000).verify(issued)).toBe(true);
});

it("takes a nonce only in the very form it made it", () => {
	const made = nonces(randomBytes(32), 1000, () => 5_000);
	const given = made.issue();
	expect(made.verify(given)).toBe(true);
	for (const other of [
		`${given} `,
		`${given}=`,
		`${given}!`,
		`0${given}`,
		// The form with a dot between its bucket and its MAC, which the Front's wire does not carry.
		partsOf(given).join("."),
		given.slice(1),
	]) {
		expect(made.verify(other), other).toBe(false);
	}
});

it("makes a nonce no one foresees without the shared secret: a 256-bit MAC over its bucket, another under another secret, a new one each bucket [rfc9449-8-a]", () => {
	const secret = randomBytes(32);
	let at = 5_000;
	const issuing = nonces(secret, 1000, () => at);
	const current = issuing.issue();
	const [bucket, mac] = partsOf(current);
	expect(Buffer.from(mac ?? "", "base64url")).toHaveLength(32);
	expect(nonces(randomBytes(32), 1000, () => at).issue()).not.toBe(current);
	at += 1000;
	const next = issuing.issue();
	expect(partsOf(next)[1]).not.toBe(mac);
	// The next bucket's nonce guessed from the current one is not taken.
	expect(issuing.verify(`${Number(bucket) + 1}${mac}`)).toBe(false);
	expect(issuing.verify(next)).toBe(true);
});

it("makes a nonce the Front's wire carries in its reply's `dpopNonce`, up to the greatest bucket", () => {
	const specs = [...replies.ok, ...replies.refused].filter((f) => f.name === "dpopNonce");
	expect(specs).toHaveLength(2);
	for (const [bucketMs, now] of [
		[1000, 5_000],
		[1000, Date.UTC(2026, 10, 26)],
		[1, Number.MAX_SAFE_INTEGER],
	] as const) {
		const made = nonces(randomBytes(32), bucketMs, () => now);
		const nonce = made.issue();
		expect(made.verify(nonce)).toBe(true);
		for (const spec of specs) {
			expect(spec.type).toBe("b64url");
			expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
			expect(nonce.length).toBeGreaterThanOrEqual(spec.min);
			expect(nonce.length).toBeLessThanOrEqual(spec.max);
		}
	}
});
