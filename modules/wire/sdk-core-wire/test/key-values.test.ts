import { describe, expect, it } from "vitest";
import { payloads, purposes, versions } from "../src/contract.ts";

describe("the statements' version and the key's thumbprint", () => {
	const key = { kty: "EC", crv: "P-256", x: "x", y: "y" } as const;
	const common = { iss: "i", sid: "s", iat: 1, exp: 2, e_enc: "e", e_sig: key, nonce: "n" };
	const named = { creation_hash: "c", credential_id: "cr", reservation_id: "r" };
	const possession = (p: object, v?: number) =>
		payloads.possession.safeParse({
			...common,
			...(v === undefined ? {} : { v }),
			purpose: purposes.possession,
			possession: { ...named, ...p },
		}).success;
	/** A passkey's thumbprint: passkey-key-wire's vector ES256's `jkt`. */
	const jkt = "f8S_bSDLrCv5BxMRxT99d2bFk8QDVQQl4bOAWUvTvCM";

	it("speaks version 1, frozen", () => {
		expect(versions).toEqual([1]);
		expect(Object.isFrozen(versions)).toBe(true);
	});

	it("names the new key by its thumbprint alone, never by its point's hash", () => {
		expect(possession({ key_jkt: jkt }, 1)).toBe(true);
		expect(possession({ key_hash: "h" }, 1)).toBe(false);
		expect(possession({ key_jkt: jkt, key_hash: "h" }, 1)).toBe(false);
		expect(possession({}, 1)).toBe(false);
	});

	it("takes a thumbprint in its one spelling alone", () => {
		expect(possession({ key_jkt: `${jkt?.slice(0, 42)}B` }, 1)).toBe(false);
		expect(possession({ key_jkt: `${jkt}=` }, 1)).toBe(false);
	});

	it("takes a version it speaks, and none without one", () => {
		expect(possession({ key_jkt: jkt }, 1)).toBe(true);
		expect(possession({ key_jkt: jkt }, 2)).toBe(false);
		expect(possession({ key_jkt: jkt })).toBe(false);
		const completion = { iss: "i", t_hash: "t", assertion_hash: "a", code: "c", iat: 1, exp: 2 };
		expect(payloads.completion.safeParse({ ...completion, v: 1 }).success).toBe(true);
		expect(payloads.completion.safeParse({ ...completion, v: 0 }).success).toBe(false);
		expect(payloads.completion.safeParse(completion).success).toBe(false);
	});

	it("binds the algorithms a creation offered, each one a passkey may be of and named once", () => {
		const creation = (algorithms?: unknown) =>
			payloads.creation.safeParse({
				...common,
				v: 1,
				purpose: purposes.creation,
				creation: {
					account: "a***",
					evidence: "ev",
					ct_hash: "ct",
					subject: "s",
					kg: 0,
					options: {
						user_id: "u",
						rp_id: "id.example",
						exclude_credentials: [],
						...(algorithms === undefined ? {} : { algorithms }),
					},
				},
			}).success;
		expect(creation()).toBe(false);
		expect(creation([-7, -8, -257])).toBe(true);
		expect(creation([])).toBe(false);
		expect(creation([-7, -7])).toBe(false);
		expect(creation([-35])).toBe(false);
	});
});
