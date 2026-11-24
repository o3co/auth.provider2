import { randomBytes } from "node:crypto";
import type { Checks } from "@mod/authority-rules";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { describe, expect, it } from "vitest";
import { algorithmNames, ceremoniesFor } from "../src/ceremony/ceremony.ts";
import type { Credential } from "../src/contract.ts";
import { type RequestOptions, softwareAuthenticator, testOrigin } from "../src/testing.ts";

const rp = {
	id: "rp.example",
	name: "RP",
	origins: [testOrigin, "https://other.rp.example"],
	topOrigins: ["https://shell.example"],
	algorithms: algorithmNames,
};
const ceremonies = ceremoniesFor(rp);
const handle = randomBytes(32).toString("base64url");
const at = { origin: testOrigin };
const fresh = () => randomBytes(32).toString("base64url");

type Algorithm = (typeof algorithmNames)[number];

async function made(authenticator = softwareAuthenticator()) {
	const challenge = fresh();
	const options = ceremonies.creation(challenge, { handle, name: "sam" }, [], "preferred");
	const attested = await ceremonies.attest(
		authenticator.create(options as never, at),
		challenge,
		handle,
		"preferred",
	);
	if (attested.kind !== "attested") throw new Error(attested.reason);
	return { authenticator, credential: attested.credential };
}
const madeBy = (algorithm: Algorithm, more: { userVerified?: boolean } = {}) =>
	made(softwareAuthenticator({ algorithm, ...more }));

/** A request over a fresh challenge naming the credential, and that challenge. */
function asked(credential: Credential, c = ceremonies) {
	const challenge = fresh();
	return { challenge, options: c.request(challenge, [credential]) as RequestOptions };
}

describe("the evidence check, state-free and at once", () => {
	it("fits authority-rules' Checks.verifyAssertion, answering the assertion's credential", async () => {
		const checks: Pick<Checks, "verifyAssertion"> = {
			verifyAssertion: ceremonies.verifyAssertion,
		};
		const { authenticator, credential } = await made();
		const { challenge, options } = asked(credential);
		const assertion = JSON.stringify(authenticator.get(options, at));
		expect(checks.verifyAssertion(assertion, credential.publicKey, challenge, testOrigin)).toEqual({
			credential: credential.id,
		});
	});

	it.each(algorithmNames)(
		"agrees with assert on what an answer must meet, verification required, for a key of %s",
		async (algorithm) => {
			const { authenticator, credential } = await madeBy(algorithm);
			const { credential: other } = await madeBy(algorithm);
			const unverifying = await madeBy(algorithm, { userVerified: false });
			const overlook = { overlook: true };
			type Case = {
				by?: typeof unverifying;
				client?: object;
				twist?: object;
				key?: Credential;
			};
			const cases: Record<string, Case> = {
				"an answer as asked": {},
				"from a frame listed": {
					client: { ...at, crossOrigin: true, topOrigin: "https://shell.example" },
				},
				"from another origin": { client: { origin: "https://evil.example" }, twist: overlook },
				"for another relying party": { twist: { rpId: "evil.example" } },
				"from a frame not listed": {
					client: { ...at, crossOrigin: true, topOrigin: "https://evil.example" },
				},
				"with no user verified": { by: unverifying, twist: overlook },
				"signed by another key": { key: { ...credential, publicKey: other.publicKey } },
				"client data that cannot be read": { twist: { clientDataJSON: () => "%%" } },
				"client data of a creation": {
					twist: {
						clientDataJSON: (json: string) =>
							Buffer.from(json.replace("webauthn.get", "webauthn.create")).toString("base64url"),
					},
				},
			};
			const answers: Record<string, boolean> = {};
			for (const [name, c] of Object.entries(cases)) {
				const by = c.by ?? { authenticator, credential };
				const { challenge, options } = asked(by.credential);
				const response = by.authenticator.get(options, (c.client ?? at) as never, c.twist ?? {});
				const key = c.key ?? by.credential;
				const asserted = await ceremonies.assert(
					response,
					{ challenge, named: true },
					key,
					"required",
				);
				const evidence = ceremonies.verifyAssertion(
					JSON.stringify(response),
					key.publicKey,
					challenge,
					testOrigin,
				);
				expect(evidence !== undefined, name).toBe(asserted.kind === "asserted");
				answers[name] = evidence !== undefined;
			}
			// Both ways, not one answer for all.
			expect(answers["an answer as asked"]).toBe(true);
			expect(answers["signed by another key"]).toBe(false);
		},
	);

	it.each(algorithmNames)(
		"answers none, as assert refuses its algorithm, where the relying party leaves %s out",
		async (algorithm) => {
			const { authenticator, credential } = await madeBy(algorithm);
			const without = ceremoniesFor({
				...rp,
				algorithms: algorithmNames.filter((name) => name !== algorithm),
			});
			const { challenge, options } = asked(credential, without);
			const response = authenticator.get(options, at);
			const asserted = await without.assert(response, { challenge, named: true }, credential);
			expect(asserted).toEqual({ kind: "refused", reason: "algorithm" });
			const evidence = without.verifyAssertion(
				JSON.stringify(response),
				credential.publicKey,
				challenge,
				testOrigin,
			);
			expect(evidence).toBeUndefined();
		},
	);

	it("answers none for an RSA key under 2048 bits", async () => {
		const { authenticator, credential } = await made(
			softwareAuthenticator({ algorithm: "RS256", rsaBits: 1024 }),
		);
		const { challenge, options } = asked(credential);
		const assertion = JSON.stringify(authenticator.get(options, at));
		expect(
			ceremonies.verifyAssertion(assertion, credential.publicKey, challenge, testOrigin),
		).toBeUndefined();
	});

	it("reads no credential state: a count since moved on, a backup state or a handle do not refuse it", async () => {
		const { authenticator, credential } = await made();
		const { challenge, options } = asked(credential);
		const response = authenticator.get(options, at, { userHandle: "someone-else" });
		const moved = { ...credential, signCount: 99, backupEligible: true };
		const asserted = await ceremonies.assert(response, { challenge, named: true }, moved);
		expect(asserted.kind).toBe("refused");
		expect(
			ceremonies.verifyAssertion(
				JSON.stringify(response),
				credential.publicKey,
				challenge,
				testOrigin,
			),
		).toEqual({ credential: credential.id });
	});

	it("answers none for another challenge or origin, or a key that is no COSE key of its algorithm", async () => {
		const { authenticator, credential } = await made();
		const { challenge, options } = asked(credential);
		const assertion = JSON.stringify(authenticator.get(options, at));
		const key = credential.publicKey;
		const check = (a: string, k: string, c: string, o: string) =>
			ceremonies.verifyAssertion(a, k, c, o);
		expect(check(assertion, key, fresh(), testOrigin)).toBeUndefined();
		// Listed for the relying party, yet not the origin asked.
		expect(check(assertion, key, challenge, "https://other.rp.example")).toBeUndefined();
		const cose = (entries: [number, unknown][]) =>
			Buffer.from(isoCBOR.encode(new Map(entries) as never)).toString("base64url");
		const xy = [
			[-2, new Uint8Array(32).fill(1)],
			[-3, new Uint8Array(32).fill(1)],
		] as [number, unknown][];
		const point = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString("base64url");
		const keys: Record<string, string> = {
			"a point off the curve": cose([[1, 2], [3, -7], [-1, 1], ...xy]),
			"an EC2 key named EdDSA": cose([[1, 2], [3, -8], [-1, 1], ...xy]),
			"an OKP key named ES256": cose([
				[1, 1],
				[3, -7],
				[-1, 6],
				[-2, new Uint8Array(32)],
			]),
			"a key with no algorithm": cose([[1, 2], [-1, 1], ...xy]),
			"a bare point": point,
			padded: `${key}=`,
			empty: "",
		};
		for (const [name, k] of Object.entries(keys)) {
			expect(check(assertion, k, challenge, testOrigin), name).toBeUndefined();
		}
	});

	it("answers none, never throwing, for a challenge of another shape, an assertion that is no JSON response, or a credential id not its raw id", async () => {
		const { authenticator, credential } = await made();
		const { challenge, options } = asked(credential);
		const response = authenticator.get(options, at);
		const key = credential.publicKey;
		for (const c of [`${challenge}=`, `${challenge}.listed`, challenge.slice(1), ""]) {
			expect(
				ceremonies.verifyAssertion(JSON.stringify(response), key, c, testOrigin),
				c,
			).toBeUndefined();
		}
		const assertions = [
			"not json",
			"null",
			"[]",
			JSON.stringify({ ...response, type: "other" }),
			JSON.stringify({ ...response, rawId: "AAAA" }),
			JSON.stringify({ ...response, response: { ...response.response, signature: 5 } }),
			JSON.stringify({ ...response, response: { ...response.response, authenticatorData: "AA" } }),
		];
		for (const assertion of assertions) {
			expect(ceremonies.verifyAssertion(assertion, key, challenge, testOrigin), assertion).toBe(
				undefined,
			);
		}
	});
});
