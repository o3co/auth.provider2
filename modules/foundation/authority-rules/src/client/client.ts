import { type Preimage, tokens } from "@mod/transparency-wire";
import type { Checks } from "../evidence/evidence.ts";

/**
 * A client's flow's rules (kernel-spec §6.1, V23): the op id and the evidence elements of a client's
 * start, its evidence read by the client's key, and its bundle's one access token.
 */

/** The longest a client's own token lives from its start's acceptance (V21): the Core narrows within it alone. */
export const lifetimeMs = 15 * 60_000;

type Refusal = string | undefined;
const segment = /^[A-Za-z0-9_-]+$/;

/** A compact JWS's signing input, its protected header and payload as received; none for any other text. */
const signingInput = (jws: string): string | undefined => {
	const parts = jws.split(".");
	return parts.length === 3 && parts.every((p) => segment.test(p))
		? `${parts[0]}.${parts[1]}`
		: undefined;
};

/** A client's start's evidence in its fixed shape: its one client assertion and its one DPoP proof. */
export interface ClientEvidence {
	readonly assertion: string;
	readonly proof: string;
}

/** What a client's start's evidence derives: its op id, its elements, the evidence by its form. */
export interface StartOf {
	readonly op: string;
	readonly elements: readonly string[];
	readonly evidence: ClientEvidence;
}

/**
 * OpIdOf and Elems (§5.2, §6.1): from a client's start's evidence, exactly one client assertion and
 * one DPoP proof, each a compact JWS, the op id `start:` and the digest of the canonical JSON of
 * `{assertion, proof}`, each its signing input, and each signing input's digest; or why not. Neither
 * the order of the evidence nor a signature goes into either.
 */
export function startOf(
	evidence: Preimage["evidence"],
	digest: (text: string) => string,
): StartOf | { readonly refused: string } {
	if (evidence.some((e) => e.form !== "clientAssertion" && e.form !== "dpopProof"))
		return { refused: "a client's start carries a client assertion and a DPoP proof alone" };
	const assertions = evidence.filter((e) => e.form === "clientAssertion");
	const proofs = evidence.filter((e) => e.form === "dpopProof");
	const [assertion] = assertions;
	const [proof] = proofs;
	if (assertions.length !== 1 || proofs.length !== 1 || !assertion || !proof)
		return { refused: "a client's start carries one client assertion and one DPoP proof" };
	const input = { assertion: signingInput(assertion.value), proof: signingInput(proof.value) };
	if (input.assertion === undefined || input.proof === undefined)
		return { refused: "a client's start's evidence is a compact JWS each" };
	// Its keys in order, its values strings: the canonical JSON.
	const op = `start:${digest(JSON.stringify({ assertion: input.assertion, proof: input.proof }))}`;
	return {
		op,
		elements: [digest(input.assertion), digest(input.proof)],
		evidence: { assertion: assertion.value, proof: proof.value },
	};
}

const isObject = (x: unknown): x is Record<string, unknown> =>
	x !== null && typeof x === "object" && !Array.isArray(x);

/** RFC 7638: a public JWK's thumbprint, its required members in order; none for another key. */
export function thumbprintOf(jwk: unknown, digest: (text: string) => string): string | undefined {
	if (!isObject(jwk)) return undefined;
	const members =
		jwk.kty === "EC"
			? ["crv", "kty", "x", "y"]
			: jwk.kty === "OKP"
				? ["crv", "kty", "x"]
				: jwk.kty === "RSA"
					? ["e", "kty", "n"]
					: undefined;
	if (!members || members.some((m) => typeof jwk[m] !== "string")) return undefined;
	return digest(JSON.stringify(Object.fromEntries(members.map((m) => [m, jwk[m]]))));
}

/** The client's record at the registry version a client's start names, as the registry holds it. */
export interface ClientAt {
	/** The public keys (JWKs) written in it. */
	readonly keys: readonly unknown[];
}

/** A client's start's evidence read by its client's key: the key's thumbprint and both payloads; or why not. */
export function evidenceRead(
	client: string,
	at: ClientAt,
	evidence: ClientEvidence,
	checks: Checks,
):
	| {
			readonly key: string;
			readonly assertion: Record<string, unknown>;
			readonly proof: Record<string, unknown>;
	  }
	| { readonly refused: string } {
	const signer = at.keys
		.map((key) => ({ key, read: checks.verifyJws(evidence.assertion, [key]) }))
		.find((s) => s.read !== undefined);
	if (!signer?.read || !isObject(signer.read.payload))
		return {
			refused: "the assertion is not signed by a key its registry version writes for the client",
		};
	const assertion = signer.read.payload;
	if (assertion.iss !== client || assertion.sub !== client)
		return { refused: "the assertion is another client's" };
	const key = thumbprintOf(signer.key, checks.digest);
	const read = checks.verifyJws(evidence.proof, [signer.key]);
	if (key === undefined || !read || !isObject(read.header) || !isObject(read.payload))
		return { refused: "the DPoP proof is not by the assertion's key" };
	if (read.header.typ !== "dpop+jwt" || thumbprintOf(read.header.jwk, checks.digest) !== key)
		return { refused: "the DPoP proof names another key than the assertion's" };
	return { key, assertion, proof: read.payload };
}

const seconds = (x: unknown) =>
	typeof x === "number" && Number.isFinite(x) ? x * 1000 : undefined;

/** Whether the evidence's times hold the acceptance time, `window` on each side: the assertion's iat (where named) to exp, the proof's iat. */
export function evidenceTimely(
	read: { readonly assertion: Record<string, unknown>; readonly proof: Record<string, unknown> },
	at: number,
	window: number,
): boolean {
	// An assertion's `iat` is optional (RFC 7523 §3); where named, it is held too.
	const named = read.assertion.iat;
	const iat = named === undefined ? Number.NEGATIVE_INFINITY : seconds(named);
	const exp = seconds(read.assertion.exp);
	const proved = seconds(read.proof.iat);
	if (iat === undefined || exp === undefined || proved === undefined) return false;
	return iat - window <= at && at <= exp + window && Math.abs(at - proved) <= window;
}

/** A compact JWS's payload, read as JSON and not verified; none for any other text. */
const payloadOf = (jws: string): Record<string, unknown> | undefined => {
	const [, payload] = jws.split(".");
	const read =
		payload === undefined ? undefined : tokens.parse(Buffer.from(payload, "base64url").toString());
	return read && "value" in read && isObject(read.value) ? read.value : undefined;
};

/**
 * Whether a client's start's evidence, its one assertion and one DPoP proof read unverified, holds
 * `at` within `window` as TimeOK reads it: for the Core to see, before its bundle, that a start the
 * rules hold to a window no narrower took (KE-C02).
 */
export function within(evidence: Preimage["evidence"], at: number, window: number): boolean {
	const one = (form: string) => {
		const values = evidence.filter((e) => e.form === form);
		return values.length === 1 ? payloadOf(values[0]?.value ?? "") : undefined;
	};
	const assertion = one("clientAssertion");
	const proof = one("dpopProof");
	return (
		assertion !== undefined &&
		proof !== undefined &&
		evidenceTimely({ assertion, proof }, at, window)
	);
}

/** What a client's bundle's start left its entry: its registry version, its key's thumbprint where read. */
export interface StartEntry {
	readonly acceptedAt: number;
	readonly version?: number | undefined;
	readonly key?: string | undefined;
}

/**
 * A client's bundle's one access token (§6.1): its texts the digest the envelope names; its subject
 * and client the flow's client; no person's authentication; one audience within the client's own
 * ceiling at its start's version (`within`); issued at its start's acceptance and gone within
 * `lifetimeMs` of it; bound to its start's key, where known.
 */
export function tokenRefusal(p: {
	readonly client: string;
	readonly digests: readonly { readonly frame: string; readonly digest: string }[] | undefined;
	readonly texts: { readonly header: string; readonly claims: string };
	readonly start: StartEntry;
	readonly checks: Checks;
}): Refusal {
	const [token, ...more] = p.digests ?? [];
	if (!token || more.length > 0 || token.frame !== "accessToken")
		return "a client's bundle issues one access token";
	const input = tokens.digestInput(p.texts.header, p.texts.claims);
	if ("error" in input || p.checks.digest(input.input) !== token.digest)
		return "the token's texts are not the digest the bundle names";
	const read = tokens.parse(p.texts.claims);
	if ("error" in read || !isObject(read.value)) return "the token's claims are no object";
	const claims = read.value;
	if (claims.sub !== p.client || claims.client_id !== p.client)
		return "a client's token is the client's own, its subject and its client";
	if (["amr", "acr", "auth_time"].some((name) => Object.hasOwn(claims, name)))
		return "a client's token names no person's authentication";
	const iat = seconds(claims.iat);
	const exp = seconds(claims.exp);
	if (iat === undefined || iat !== Math.floor(p.start.acceptedAt / 1000) * 1000)
		return "a client's token is issued at its start's acceptance";
	if (exp === undefined || exp > p.start.acceptedAt + lifetimeMs)
		return "a client's token is gone within fifteen minutes of its start";
	const cnf = claims.cnf;
	if (p.start.key !== undefined && !(isObject(cnf) && cnf.jkt === p.start.key))
		return "a client's token is bound to the key its start's evidence was signed by";
	const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
	const [audience, ...others] = audiences;
	if (typeof audience !== "string" || others.length > 0)
		return "a client's token names one audience";
	const scope = claims.scope === undefined ? "" : claims.scope;
	const within = p.checks.selfCeiling;
	if (
		within &&
		p.start.version !== undefined &&
		(typeof scope !== "string" || !within(p.client, p.start.version, audience, scope))
	)
		return "the audience and scope are not within the client's own ceiling";
	return undefined;
}
