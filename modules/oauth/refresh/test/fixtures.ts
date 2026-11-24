import type { FamilyRequest } from "@mod/code-grant";
import { payloads } from "@mod/sdk-core-wire";
import { familyRecordsInMemory } from "../src/testing.ts";

export const now = 1_800_000_000_000;
export const lifetimeMs = 86_400_000;
export const jkt = "k-jkt";

/** A statement T's payload, as the schema takes it, issued at `iat` (seconds). */
export const statementPayload = (iat = now / 1000 - 10, over: Record<string, unknown> = {}) => ({
	v: 1,
	iss: "https://issuer.example",
	sid: "sid-1",
	iat,
	exp: iat + 300,
	e_enc: "ZW5j",
	e_sig: { kty: "EC", crv: "P-256", x: "x", y: "y" },
	purpose: "authorization",
	approval: {
		client_id: "app",
		redirect_uri: "https://app.example/cb",
		response_type: "code",
		response_mode: "form_post",
		state: "st",
		scope: "openid read write",
		nonce: "n",
		code_challenge: "c".repeat(43),
		code_challenge_method: "S256",
		dpop_jkt: jkt,
		jar_hash: "jh",
		...over,
	},
});
/** A compact JWS whose payload is `payload`, its signature a stand-in. */
export const jws = (payload: object) =>
	`eyJhbGciOiJFUzI1NiJ9.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.c2ln`;
export const statement = jws(statementPayload());
if (!payloads.statement.safeParse(statementPayload()).success)
	throw new Error("a statement the schema refuses");

export const binding = { member: "jkt", confirmation: jkt, tokenType: "DPoP" } as const;

/** A family's request, as `code-grant` asks it of a redemption. */
export const request: FamilyRequest = {
	subject: "alice",
	clientId: "app",
	scope: ["read"],
	audience: ["https://api"],
	amr: ["pop", "user"],
	session: "sess-1",
	binding,
	code: "code-digest",
	esig: "e",
	apr: { shard: "s1", n: 3 },
	approvedAt: now - 5_000,
	statement: "t-hash",
};

/** refresh's records in memory, on a clock the test moves. */
export function recordsAt() {
	let at = now;
	const clock = () => at;
	return { ...familyRecordsInMemory(clock), move: (ms: number) => (at += ms), now: clock };
}
