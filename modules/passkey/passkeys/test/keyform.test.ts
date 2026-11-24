import { createHash } from "node:crypto";
import { allowed, emptyState, type FlowState } from "@mod/authority-rules";
import { challengeInput, typs } from "@mod/sdk-core-wire";
import { ceremonies, keyThumbprint } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { world } from "./fixtures/world.ts";

const digest = (data: string | Uint8Array) => createHash("sha256").update(data).digest("base64url");
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** A statement as the rules read it here: `header.payload.kid`, verified where its kid is the ring's. */
const ring = [{ kid: "ring-1" }];
const signed = (payload: unknown) =>
	`${b64({ alg: "ES256", typ: typs.statement })}.${b64(payload)}.ring-1`;
const iat = 1_700_000_000;
const t = signed({
	v: 1,
	iss: "https://core.example",
	sid: "t-1",
	iat,
	exp: iat + 300,
	e_enc: "ZW5j",
	e_sig: { kty: "EC", crv: "P-256", x: "eA", y: "eQ" },
	purpose: "authorization",
	approval: {
		client_id: "rp",
		redirect_uri: "https://rp.example/cb",
		response_type: "code",
		response_mode: "form_post",
		state: "st",
		scope: "openid",
		nonce: "n",
		code_challenge: "cc",
		code_challenge_method: "S256",
		dpop_jkt: "jkt",
		jar_hash: "jh",
	},
});

describe("the key passkeys keeps, one form for webauthn and the rules", () => {
	it.each(["ES256", "EdDSA", "RS256"] as const)(
		"keeps a %s key as its COSE_Key, which passkeys' assert and the rules' approval both take",
		async (algorithm) => {
			const w = await world({ webauthn: { algorithms: ["ES256", "EdDSA", "RS256"] } });
			const auth = softwareAuthenticator({ algorithm });
			const { credential } = await w.register("s1", true, auth);
			const held = w.frames.value("s1", "keys") as { keys: FlowState["keys"] };
			const [[id, key] = []] = Object.entries(held.keys);
			expect(key?.publicKey).toBe(credential.publicKey);
			const alg = { ES256: -7, EdDSA: -8, RS256: -257 }[algorithm];
			expect(keyThumbprint(key?.publicKey ?? "")?.alg).toBe(alg);

			const named = w.asserting([credential], auth);
			expect(
				await w.keys.assert(named.response, { ...named, allow: [credential.id] }),
			).toMatchObject({ kind: "asserted", subject: "s1", credential: credential.id });

			const cer = await w.app.get(ceremonies);
			const challenge = digest(challengeInput(t, "get"));
			const asserted = JSON.stringify(
				auth.get(cer.request(challenge, [credential]) as never, { origin: testOrigin }),
			);
			const ask = {
				record: {
					v: 1,
					kind: "approval",
					flow: { of: "subject", id: "s1" },
					op: "op-2",
					stage: 1,
					last: true,
					plaintextDigest: "p".repeat(43),
					id: "r-2",
					writer: { role: "core", instance: "i-1", image: "img", generation: 1 },
					position: 2,
					shard: "s1",
					n: 2,
					acceptedAt: (iat + 1) * 1000,
					sealedTo: [{ key: "mk-1", ciphertextHash: "c".repeat(43) }],
					keySetVersion: 1,
					approval: { statement: digest(t), assertion: digest(asserted), code: digest("code") },
				},
				preimage: {
					v: 1,
					parent: id,
					evidence: [
						{ form: "statement", value: t },
						{ form: "assertion", value: asserted },
					],
					content: {},
				},
				state: { ...emptyState, keys: held.keys },
				prior: [],
				checks: {
					verifyJws: (jws: string, keys: readonly unknown[]) => {
						const [header, payload, kid] = jws.split(".");
						const known = keys.some((k) => (k as { kid?: string }).kid === kid);
						return known && header && payload
							? {
									header: JSON.parse(Buffer.from(header, "base64url").toString()),
									payload: JSON.parse(Buffer.from(payload, "base64url").toString()),
								}
							: undefined;
					},
					verifyAssertion: cer.verifyAssertion,
					digest,
					keyThumbprint,
				},
				context: {
					ring,
					origin: testOrigin,
					limits: {
						codeLifetime: 1,
						refreshLifetime: 1,
						issueWindow: 1,
						epsilon: 0,
						propagation: 0,
						retry: 0,
					},
				},
			} as Parameters<typeof allowed>[0];
			expect(allowed(ask)).toEqual({ allowed: true });
		},
	);
});
