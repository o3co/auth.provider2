import { logTyps, tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { digest } from "../src/bytes.ts";
import { checkCallback } from "../src/callback.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const expected = { iss: "https://id.example", client_id: "c1", state: "s1", code: "code-1" };
const apr = { shard: "s1", n: 7 };

async function world(change: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
	const eSig = await signingKey("ES256");
	const { alg: _alg, kid: _kid, ...jwk } = eSig.jwk;
	const body = {
		iss: expected.iss,
		client_id: expected.client_id,
		state: expected.state,
		code_hash: await digest(expected.code),
		apr,
		iat: 1_700_000_000,
		...change,
	};
	const proof = await signCompact(eSig, body, {
		kid: undefined,
		typ: logTyps.callback,
		jwk,
		...header,
	});
	const esig = await digest(tokens.ecThumbprintInput(jwk) ?? "");
	const idToken = { esig, apr, iss: expected.iss, aud: expected.client_id };
	return { eSig, jwk, proof, idToken };
}

describe("checkCallback (R18)", () => {
	it("takes a proof signed by T's E_sig, naming the ID token's record and the expected request", async () => {
		const { proof, idToken } = await world();
		expect(await checkCallback({ proof, idToken, expected })).toEqual({ ok: true });
	});

	it("refuses a proof not signed by the key its header carries, unreadable, or of another typ or algorithm", async () => {
		const { proof, idToken } = await world();
		const [h, p, s = ""] = proof.split(".");
		const other = await world({ iat: 1 });
		for (const bad of [
			`${h}.${p}.${(other.proof.split(".")[2] ?? "").slice(0, -2)}AA`,
			`${h}.${p}`,
			"x.y.z",
			`${h}.${other.proof.split(".")[1]}.${s}`,
		])
			expect(await checkCallback({ proof: bad, idToken, expected }), bad).toEqual({
				fault: "proof",
			});
		for (const header of [{ typ: "approval+jwt" }, { kid: "k" }, { crit: ["x"] }]) {
			const w = await world({}, header);
			expect(
				await checkCallback({ proof: w.proof, idToken: w.idToken, expected }),
				JSON.stringify(header),
			).toEqual({
				fault: "proof",
			});
		}
		const extra = await world({ c_hash: "x" });
		expect(await checkCallback({ proof: extra.proof, idToken: extra.idToken, expected })).toEqual({
			fault: "proof",
		});
	});

	it("refuses a proof whose key is not the one the ID token names: another screen signed it", async () => {
		const { proof } = await world();
		const theirs = await world();
		expect(await checkCallback({ proof, idToken: theirs.idToken, expected })).toEqual({
			fault: "key",
		});
	});

	it("refuses a proof naming another record than the ID token's apr: two approvals for one code", async () => {
		const { proof, idToken } = await world();
		for (const other of [
			{ shard: "s2", n: 7 },
			{ shard: "s1", n: 8 },
		])
			expect(await checkCallback({ proof, idToken: { ...idToken, apr: other }, expected })).toEqual(
				{
					fault: "apr",
				},
			);
	});

	it("refuses a proof or an ID token naming another issuer, client, state or code", async () => {
		const { proof, idToken } = await world();
		for (const change of [
			{ iss: "https://other.example" },
			{ client_id: "c2" },
			{ state: "s2" },
			{ code: "code-2" },
		])
			expect(
				await checkCallback({ proof, idToken, expected: { ...expected, ...change } }),
				JSON.stringify(change),
			).toEqual({ fault: "field" });
		for (const change of [{ iss: "https://other.example" }, { aud: "c2" }])
			expect(
				await checkCallback({ proof, idToken: { ...idToken, ...change }, expected }),
				JSON.stringify(change),
			).toEqual({ fault: "field" });
	});
});
