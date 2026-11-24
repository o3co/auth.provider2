import { randomBytes } from "node:crypto";
import type { Checks } from "@mod/authority-rules";
import { cose, decodeCredentialPublicKey } from "@simplewebauthn/server/helpers";
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

/** A credential's COSE P-256 key as the evidence names it: its uncompressed point, base64url. */
function pointOf(credential: Credential): string {
	const key = decodeCredentialPublicKey(Buffer.from(credential.publicKey, "base64url")) as Map<
		number,
		unknown
	>;
	const x = key.get(cose.COSEKEYS.x) as Uint8Array;
	const y = key.get(cose.COSEKEYS.y) as Uint8Array;
	return Buffer.concat([Buffer.from([4]), x, y]).toString("base64url");
}

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
		expect(checks.verifyAssertion(assertion, pointOf(credential), challenge, testOrigin)).toEqual({
			credential: credential.id,
		});
	});

	it("agrees with assert on what an answer must meet, verification required", async () => {
		const { authenticator, credential } = await made();
		const { credential: other } = await made();
		const unverifying = await made(softwareAuthenticator({ userVerified: false }));
		const overlook = { overlook: true };
		type Case = { by?: typeof unverifying; client?: object; twist?: object; key?: Credential };
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
			"signed by another key": { key: other },
			"client data that cannot be read": { twist: { clientDataJSON: () => "%%" } },
			"client data of a creation": {
				twist: {
					clientDataJSON: (json: string) =>
						Buffer.from(json.replace("webauthn.get", "webauthn.create")).toString("base64url"),
				},
			},
		};
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
				pointOf(key),
				challenge,
				testOrigin,
			);
			expect(evidence !== undefined, name).toBe(asserted.kind === "asserted");
		}
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
				pointOf(credential),
				challenge,
				testOrigin,
			),
		).toEqual({ credential: credential.id });
	});

	it("answers none for another challenge, origin, key, or one that is no P-256 point", async () => {
		const { authenticator, credential } = await made();
		const { challenge, options } = asked(credential);
		const assertion = JSON.stringify(authenticator.get(options, at));
		const key = pointOf(credential);
		const check = (a: string, k: string, c: string, o: string) =>
			ceremonies.verifyAssertion(a, k, c, o);
		expect(check(assertion, key, fresh(), testOrigin)).toBeUndefined();
		// Listed for the relying party, yet not the origin asked.
		expect(check(assertion, key, challenge, "https://other.rp.example")).toBeUndefined();
		const notOnCurve = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString("base64url");
		const compressed = Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 1)]).toString("base64url");
		for (const k of [notOnCurve, compressed, credential.publicKey, `${key}=`, ""]) {
			expect(check(assertion, k, challenge, testOrigin), k).toBeUndefined();
		}
	});

	it("answers none, never throwing, for a challenge of another shape, an assertion that is no JSON response, or a credential id not its raw id", async () => {
		const { authenticator, credential } = await made();
		const { challenge, options } = asked(credential);
		const response = authenticator.get(options, at);
		const key = pointOf(credential);
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

	it("answers none where the relying party takes ES256 no longer", async () => {
		const { authenticator, credential } = await made();
		const elsewhere = ceremoniesFor({ ...rp, algorithms: ["EdDSA", "RS256"] });
		const { challenge, options } = asked(credential);
		const assertion = JSON.stringify(authenticator.get(options, at));
		expect(
			elsewhere.verifyAssertion(assertion, pointOf(credential), challenge, testOrigin),
		).toBeUndefined();
	});
});
