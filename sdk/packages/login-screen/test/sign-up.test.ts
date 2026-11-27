import { continuations } from "@mod/continuation-wire";
import { purposes, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { digest, utf8 } from "../src/bytes.ts";
import { firstKey } from "../src/first-key/first-key.ts";
import { screenKeys } from "../src/keys.ts";
import { signUp } from "../src/sign-up/sign-up.ts";
import { readPushedT, readT, signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";

/** A T the screen read (by value, or under PAR), and the sign-up creation the Core would answer its continuation with. */
async function world(reading: typeof readT = readT) {
	const ring = await signingKey("ES256", "core-1");
	const keys = await screenKeys();
	const { tCompact, t } = await reading(ring, keys);
	const options = { ring: [ring.jwk], keys, issuer };
	const sign = (payload: unknown) => signCompact(ring, payload, { typ: typs.statement });
	const common = {
		v: 1,
		iss: issuer,
		sid: "st-1",
		iat: 1,
		exp: 2,
		e_enc: keys.eEnc,
		e_sig: keys.eSig,
	};
	const creation = async (over: Record<string, unknown> = {}) =>
		sign({
			...common,
			nonce: "cn",
			purpose: purposes.creation,
			creation: {
				basis: "sign-up",
				evidence: await digest(tCompact),
				subject: "sub-new",
				kg: 0,
				options: {
					user_id: "dXNlcg",
					user_name: "Example 7f3a",
					rp_id: "id.example",
					exclude_credentials: [],
					algorithms: [-7],
				},
				...over,
			},
		});
	return { ring, keys, tCompact, options, t, creation, sign };
}

describe("sign-up from a T read under PAR", () => {
	it("takes a T readPushed gave as one read gave: its continuation, and its creation read", async () => {
		const w = await world(readPushedT);
		expect(await signUp.continuation(w.t, w.keys)).toMatchObject({ stage: "sign-up", seq: 1 });
		expect("creation" in (await signUp.readCreation(await w.creation(), w.t, w.options))).toBe(
			true,
		);
		expect(await signUp.continuation({ ...w.t }, w.keys)).toEqual({ error: "statement" });
	});
});

describe("signUp.continuation", () => {
	it("signs T's sign-up stage with E_sig, sequence 1, its body {}", async () => {
		const w = await world();
		const sent = await signUp.continuation(w.t, w.keys);
		if ("error" in sent) throw new Error(sent.error);
		expect({ stage: sent.stage, seq: sent.seq, body: sent.body }).toEqual({
			stage: "sign-up",
			seq: 1,
			body: "{}",
		});
		const input = continuations.of("sign-up", await digest(w.tCompact), 1, await digest("{}"));
		const key = await crypto.subtle.importKey(
			"jwk",
			{ ...w.keys.eSig },
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		const signature = Buffer.from(sent.sig, "base64url");
		expect(signature).toHaveLength(64);
		expect(
			await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, utf8(input)),
		).toBe(true);
	});

	it("refuses a T it did not read, and keys other than the ones T names", async () => {
		const w = await world();
		expect(await signUp.continuation({ ...w.t }, w.keys)).toEqual({ error: "statement" });
		expect(await signUp.continuation(w.t, await screenKeys())).toEqual({ error: "keys" });
	});
});

describe("signUp.readCreation", () => {
	it("reads sign-up's creation, which the first key's next steps take, its account named by user_name", async () => {
		const w = await world();
		const read = await signUp.readCreation(await w.creation(), w.t, w.options);
		if ("error" in read) throw new Error(read.error);
		expect(read.creation.statement.creation.account).toBeUndefined();
		const asked = await firstKey.createOptions(read.creation, { rpName: "Example" });
		if ("error" in asked) throw new Error(asked.error);
		expect(asked.options.user).toMatchObject({ name: "Example 7f3a", displayName: "Example 7f3a" });
	});

	it("refuses another path's creation, another T's evidence, an account, no name, a T it did not read, and keys other than T's", async () => {
		const w = await world();
		const options = {
			user_id: "dXNlcg",
			rp_id: "id.example",
			exclude_credentials: [],
			algorithms: [-7],
		};
		for (const [over, error] of [
			// A passkey-add's names its approving key (V30): of the schema's form, not a real key.
			[
				{
					basis: "passkey-add",
					account: "a***",
					approver_key: { kty: "EC", crv: "P-256", x: "A".repeat(43), y: "A".repeat(43) },
					options,
				},
				"basis",
			],
			[{ evidence: await digest("another T") }, "evidence"],
			[{ account: "a***" }, "payload"],
			[{ options }, "payload"],
		] as const)
			expect(
				await signUp.readCreation(await w.creation(over), w.t, w.options),
				JSON.stringify(over),
			).toEqual({ error });
		expect(await signUp.readCreation(await w.creation(), { ...w.t }, w.options)).toEqual({
			error: "statement",
		});
		const keys = await screenKeys();
		expect(await signUp.readCreation(await w.creation(), w.t, { ...w.options, keys })).toEqual({
			error: "keys",
		});
	});
});
