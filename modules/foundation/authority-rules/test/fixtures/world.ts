import { createHash } from "node:crypto";
import { challengeInput, typs } from "@mod/sdk-core-wire";
import type { LogRecord } from "@mod/transparency-wire";
import type { Checks, Context } from "../../src/evidence/evidence.ts";

/**
 * A test world for the rules: a JWS is `header.payload.kid`, verified where its kid is one of the
 * keys'; an assertion is base64url JSON of what it was made with; digests are SHA-256.
 */

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const unb64 = (text: string): unknown => JSON.parse(Buffer.from(text, "base64url").toString());

export const digest = (data: string | Uint8Array) =>
	createHash("sha256").update(data).digest("base64url");

const algorithms = [-7, -8, -257];
/** A passkey's COSE_Key as this world reads it: a map's head, its algorithm's index, then `seed`'s bytes. */
export const coseKey = (seed: number, alg = -7) =>
	Buffer.from([0xa5, algorithms.indexOf(alg), ...Buffer.alloc(32, seed)]).toString("base64url");

export const checks: Checks = {
	verifyJws(jws, keys) {
		const [header, payload, kid, ...rest] = jws.split(".");
		if (!header || !payload || !kid || rest.length > 0) return undefined;
		if (!keys.some((k) => (k as { kid?: string }).kid === kid)) return undefined;
		return { header: unb64(header), payload: unb64(payload) };
	},
	verifyAssertion(assertion, publicKey, challenge, origin) {
		const made = unb64(assertion) as Record<string, string>;
		const holds =
			made.publicKey === publicKey && made.challenge === challenge && made.origin === origin;
		return holds && made.credential ? { credential: made.credential } : undefined;
	},
	digest,
	keyThumbprint(publicKey) {
		const bytes = Buffer.from(publicKey, "base64url");
		const alg = bytes[0] === 0xa5 ? algorithms[bytes[1] ?? -1] : undefined;
		return alg === undefined ? undefined : { jkt: digest(`jkt:${publicKey}`), alg };
	},
};

/** The ring of a Core generation: one key, its kid naming the generation. */
export const ring = (generation: number) => [{ kid: `ring-${generation}` }];
export const sign = (payload: unknown, kid: string, typ: string = typs.statement) =>
	`${b64({ alg: "ES256", typ })}.${b64(payload)}.${kid}`;

export const origin = "https://login.example";
export const limits = {
	codeLifetime: 60_000,
	refreshLifetime: 3_600_000,
	issueWindow: 2_000,
	epsilon: 1_000,
	propagation: 2_000,
	retry: 1_000,
};
export const context = (generation = 1): Context => ({ ring: ring(generation), origin, limits });

/** A passkey's assertion over a statement, as the key made it. */
export const assertion = (
	key: { credential: string; publicKey: string },
	statement: string,
	at = origin,
) =>
	b64({
		credential: key.credential,
		publicKey: key.publicKey,
		challenge: digest(challengeInput(statement, "get")),
		origin: at,
	});

export const T0 = 1_700_000_000;
const screen = {
	v: 1,
	e_enc: "ZW5j",
	e_sig: { kty: "EC", crv: "P-256", x: "eA", y: "eQ" },
};
/** The statement T of an authorization, valid from `iat` (seconds) for five minutes. */
export const authorization = (sid: string, iat = T0) => ({
	iss: "https://core.example",
	sid,
	iat,
	exp: iat + 300,
	...screen,
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
export const creation = (subject: string, iat = T0, kg = 0, offered = algorithms) => ({
	iss: "https://core.example",
	sid: "creation-1",
	iat,
	exp: iat + 300,
	...screen,
	nonce: "n1",
	purpose: "creation",
	creation: {
		account: "a***@example",
		evidence: "ev",
		ct_hash: "ct",
		subject,
		kg,
		options: {
			user_id: "u",
			rp_id: "login.example",
			exclude_credentials: [],
			algorithms: offered,
		},
	},
});
export const possession = (
	creationJws: string,
	key: { credential: string; publicKey: string },
	iat = T0,
) => ({
	iss: "https://core.example",
	sid: "possession-1",
	iat,
	exp: iat + 300,
	...screen,
	nonce: "n2",
	purpose: "possession",
	possession: {
		creation_hash: digest(creationJws),
		key_jkt: checks.keyThumbprint(key.publicKey)?.jkt,
		credential_id: key.credential,
		reservation_id: "res-1",
	},
});

export const subject = { of: "subject", id: "sub-1" } as const;
export type FlowRecord = Exclude<LogRecord, { kind: "tick" }>;
const d = (c: string) => c.repeat(43);

/** A Core writer's record of generation 1 at a flow position, accepted at `T0` + `at` ms. */
export const coreRecord = (
	kind: FlowRecord["kind"],
	position: number,
	over: Partial<FlowRecord> = {},
): FlowRecord =>
	({
		v: 1,
		kind,
		flow: subject,
		op: `op-${position}`,
		stage: 1,
		last: true,
		plaintextDigest: d("p"),
		id: `r-${position}`,
		writer: { role: "core", instance: "i-1", image: "img", generation: 1 },
		position,
		shard: "s1",
		n: position,
		acceptedAt: T0 * 1000 + 1000 * position,
		sealedTo: [{ key: "mk-1", ciphertextHash: d("c") }],
		keySetVersion: 1,
		...over,
	}) as FlowRecord;

/** A monitor writer's record on the flow (a confirmation, a denial, a boundary), its body apart. */
export const monitorRecord = (kind: FlowRecord["kind"], position: number): FlowRecord =>
	({
		v: 1,
		kind,
		flow: subject,
		op: `op-${position}`,
		stage: 1,
		last: true,
		plaintextDigest: d("p"),
		signed: "c2lnbmVk",
		id: `r-${position}`,
		writer: { role: "monitor", key: "mon-1" },
		position,
		shard: "s1",
		n: position,
		acceptedAt: T0 * 1000 + 1000 * position,
	}) as FlowRecord;

export const preimage = (over: {
	root?: string;
	parent?: string;
	evidence?: { form: string; value: string }[];
	content?: Record<string, unknown>;
}) => ({ v: 1, evidence: [], content: {}, ...over });
