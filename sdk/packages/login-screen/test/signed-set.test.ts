import { logTyps } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { readSet, readSetSigned } from "../src/signed-set.ts";

/** The set read as the screen reads it, then the object by it; a set that does not read gives none. */
const readBy = async (text: string, signers: unknown, purpose: "status" | "stateOf") => {
	const set = readSet(signers);
	return set && readSetSigned(text, set, purpose);
};

import { signCompact, signingKey } from "./fixtures.ts";

type Key = Awaited<ReturnType<typeof signingKey>>;
const publicOf = (key: Key, kid = key.kid) => {
	const { kty, crv, x, y } = key.jwk;
	return { kid, key: { kty, crv, x, y } };
};
async function signed(payload: unknown, signers: readonly (readonly [Key, string])[], typ: string) {
	const signatures = [];
	let body = "";
	for (const [key, kid] of signers) {
		const [p = "", b = "", s = ""] = (await signCompact(key, payload, { typ, kid })).split(".");
		body = b;
		signatures.push({ protected: p, signature: s });
	}
	return JSON.stringify({ payload: body, signatures });
}

// The same cases as rp-kit's status reading, so the two copies of the rule do not drift.
describe("readSetSigned", () => {
	it("reads an object enough of its set signed, of the purpose's typ", async () => {
		const a = await signingKey("ES256", "a");
		const b = await signingKey("ES256", "b");
		const set = {
			v: 1,
			version: 1,
			purpose: "status",
			keys: [publicOf(a), publicOf(b)],
			required: 2,
		};
		const text = await signed(
			{ x: 1 },
			[
				[a, "a"],
				[b, "b"],
			],
			logTyps.status,
		);
		expect(await readBy(text, set, "status")).toEqual({ x: 1 });
	});

	it("counts one key named under two kids once, a signature of another typ none, and refuses a set of another purpose", async () => {
		const a = await signingKey("ES256", "a");
		const b = await signingKey("ES256", "b");
		const twice = {
			v: 1,
			version: 1,
			purpose: "status",
			keys: [publicOf(a, "a"), publicOf(a, "a2")],
			required: 2,
		};
		expect(
			await readBy(
				await signed(
					{ x: 1 },
					[
						[a, "a"],
						[a, "a2"],
					],
					logTyps.status,
				),
				twice,
				"status",
			),
		).toBeUndefined();
		const set = {
			v: 1,
			version: 1,
			purpose: "status",
			keys: [publicOf(a), publicOf(b)],
			required: 2,
		};
		expect(
			await readBy(
				await signed(
					{ x: 1 },
					[
						[a, "a"],
						[b, "b"],
					],
					logTyps.stateOf,
				),
				set,
				"status",
			),
		).toBeUndefined();
		const text = await signed(
			{ x: 1 },
			[
				[a, "a"],
				[b, "b"],
			],
			logTyps.status,
		);
		expect(await readBy(text, { ...set, purpose: "stateOf" }, "status")).toBeUndefined();
		expect(await readBy(text, set, "stateOf")).toBeUndefined();
	});

	it("refuses fewer signers than required, and a text that is no set's signed object", async () => {
		const a = await signingKey("ES256", "a");
		const b = await signingKey("ES256", "b");
		const set = {
			v: 1,
			version: 1,
			purpose: "status",
			keys: [publicOf(a), publicOf(b)],
			required: 2,
		};
		expect(
			await readBy(await signed({ x: 1 }, [[a, "a"]], logTyps.status), set, "status"),
		).toBeUndefined();
		for (const text of ["", "{", "[]", "{}", "a.b.c"])
			expect(await readBy(text, set, "status"), text).toBeUndefined();
	});
});
