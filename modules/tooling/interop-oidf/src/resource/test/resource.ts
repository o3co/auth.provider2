/**
 * The resource the OIDF run calls with its access tokens: the harness's, as nextgen offers no resource
 * server yet. It takes a DPoP-bound access token of the provider's (RFC 9068: its type, its signature by
 * the authority's published keys, its issuer, its audience, its time) with a DPoP proof (RFC 9449 §4.3,
 * §7) of the key the token is bound to, behind an https front at the resource's origin. Its checks are
 * the harness's, never the provider's: a run's result here speaks of the token and the proof the
 * provider issued and bound, and of this resource's own checks.
 */
import { constants, createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { type Front, selfSigned, startFront } from "@mod/conformance-front";
import { stopAll } from "../../lifecycle/lifecycle.ts";

const b64u = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");
const sha256 = (text: string) => createHash("sha256").update(text).digest();
const seconds = () => Math.floor(Date.now() / 1000);

/** The algorithms a proof and a token are taken under, each with the key it takes (FAPI 2.0 §5.4.1). */
const algorithms: ReadonlyMap<
	string,
	{
		readonly kty: string;
		readonly crv?: string;
		readonly minBits?: number;
		readonly hash: string | null;
	}
> = new Map([
	["ES256", { kty: "EC", crv: "P-256", hash: "sha256" }],
	["PS256", { kty: "RSA", minBits: 2048, hash: "sha256" }],
	["EdDSA", { kty: "OKP", crv: "Ed25519", hash: null }],
]);

/** The algorithms a refusal names as taken for a proof (RFC 9449 §7.1's `algs`). */
const algs = [...algorithms.keys()].join(" ");

/** How far a proof's `iat` may be from now, either way. */
const proofWindowS = 60;

/** A key as a JWKS or a proof writes it. */
type Jwk = Readonly<Record<string, unknown>>;

/** RFC 7638's thumbprint of a public key: its required members, in order, hashed (OKP's by RFC 8037 §2). */
export function thumbprintOf(jwk: Jwk): string | undefined {
	const members =
		jwk.kty === "EC"
			? ["crv", "kty", "x", "y"]
			: jwk.kty === "RSA"
				? ["e", "kty", "n"]
				: jwk.kty === "OKP"
					? ["crv", "kty", "x"]
					: undefined;
	if (members === undefined || members.some((m) => typeof jwk[m] !== "string")) return undefined;
	return b64u(sha256(JSON.stringify(Object.fromEntries(members.map((m) => [m, jwk[m]])))));
}

/** A base64url segment written as its bytes encode: no padding, no other letter, no bits left over. */
const canonical = (part: string) =>
	/^[A-Za-z0-9_-]+$/.test(part) && Buffer.from(part, "base64url").toString("base64url") === part;

/**
 * A compact JWS read (RFC 7515 §5.2): three base64url segments, its header and claims JSON objects, its
 * `alg` a string, no `crit` (no extension is understood here, §4.1.11); or none where it is not.
 */
function jwsOf(text: string) {
	const parts = text.split(".");
	if (parts.length !== 3 || parts.some((part) => !canonical(part))) return undefined;
	const [head = "", body = "", signature = ""] = parts;
	try {
		const header = JSON.parse(Buffer.from(head, "base64url").toString("utf8"));
		const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
		if (typeof header !== "object" || header === null || Array.isArray(header)) return undefined;
		if (typeof claims !== "object" || claims === null || Array.isArray(claims)) return undefined;
		if (typeof header.alg !== "string" || "crit" in header) return undefined;
		return {
			header: header as Record<string, unknown> & { readonly alg: string },
			claims: claims as Record<string, unknown>,
			input: Buffer.from(`${head}.${body}`),
			signature: Buffer.from(signature, "base64url"),
		};
	} catch {
		return undefined;
	}
}

type Jws = NonNullable<ReturnType<typeof jwsOf>>;

/** The public key a JWK names, where its algorithm is one taken and the key is one that algorithm takes. */
function keyFor(alg: string, jwk: Jwk): KeyObject | undefined {
	const taken = algorithms.get(alg);
	if (taken === undefined || taken.kty !== jwk.kty) return undefined;
	if (taken.crv !== undefined && jwk.crv !== taken.crv) return undefined;
	try {
		const key = createPublicKey({ key: jwk, format: "jwk" } as Parameters<
			typeof createPublicKey
		>[0]);
		const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
		if (taken.minBits !== undefined && bits < taken.minBits) return undefined;
		return key;
	} catch {
		return undefined;
	}
}

/** Whether a JWS is signed by this key (one its algorithm takes). */
function signedBy(jws: Jws, key: KeyObject): boolean {
	const hash = algorithms.get(jws.header.alg)?.hash ?? null;
	try {
		return verify(
			hash,
			jws.input,
			{
				key,
				...(key.asymmetricKeyType === "ec" ? { dsaEncoding: "ieee-p1363" as const } : {}),
				...(key.asymmetricKeyType === "rsa"
					? { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
					: {}),
			},
			jws.signature,
		);
	} catch {
		return false;
	}
}

/** A media type as `typ` writes it, compared in any case, `application/` left out (RFC 7515 §4.1.9). */
const typOf = (value: unknown) =>
	typeof value === "string" ? value.toLowerCase().replace(/^application\//, "") : undefined;

/** A URL as RFC 9449 §4.3 compares `htu`: scheme, host and port (defaults resolved, case folded) and path. */
const htuOf = (text: string) => {
	try {
		const url = new URL(text);
		if (url.username !== "" || url.password !== "") return undefined;
		return `${url.protocol}//${url.host}${url.pathname}`;
	} catch {
		return undefined;
	}
};

/**
 * Why a request is refused, and in what words (RFC 6750 §3, RFC 9449 §7.1); a request with no
 * credentials at all is answered with no error (RFC 6750 §3.1).
 */
export type Refused = {
	readonly status: number;
	readonly error?: string;
	readonly description?: string;
};

/** The resource started: its URL, the certificate its front answers with, what it refused, and its stop. */
export interface Resource {
	readonly url: string;
	readonly certificate: string;
	readonly refused: () => readonly Refused[];
	stop(): Promise<void>;
}

/** The path the resource answers at its origin. */
const path = "/resource";

/**
 * Starts the resource at `host` (listening on `listen`), taking tokens of `issuer` for `audience`,
 * signed by the keys `jwks` gives (each read at every call, so it can start before the provider).
 */
export async function startResource(options: {
	readonly host: string;
	readonly listen: string;
	readonly dir: string;
	readonly issuer: () => string;
	readonly audience: () => string;
	readonly jwks: () => Promise<readonly Jwk[]>;
}): Promise<Resource> {
	const refusals: Refused[] = [];
	const spent = new Set<string>();
	let origin = "";
	const check = async (req: IncomingMessage): Promise<Refused | Record<string, unknown>> => {
		const token = (description: string): Refused => ({
			status: 401,
			error: "invalid_token",
			description,
		});
		const proofRefused = (description: string): Refused => ({
			status: 401,
			error: "invalid_dpop_proof",
			description,
		});
		// The origin is the resource's own, never the request's: an absolute or `//` target names no other.
		const target = new URL(`${origin}${req.url?.startsWith("/") ? req.url : "/"}`);
		if (target.pathname !== path)
			return { status: 404, error: "not_found", description: "no such path" };
		if (target.searchParams.has("access_token"))
			return { status: 400, error: "invalid_request", description: "a token in the query" };
		const authorization = req.headers.authorization;
		if (authorization === undefined || authorization === "") return { status: 401 };
		const [, scheme = "", value = ""] = /^(\S+) +(\S+)$/.exec(authorization) ?? [];
		if (scheme.toLowerCase() !== "dpop") return token("a DPoP-bound token, sent as DPoP");
		const at = jwsOf(value);
		if (at === undefined) return token("the token is no JWS");
		if (typOf(at.header.typ) !== "at+jwt") return token("the token's typ");
		const published = (await options.jwks()).find(
			(k) =>
				typeof at.header.kid === "string" &&
				k.kid === at.header.kid &&
				(k.use === undefined || k.use === "sig") &&
				(k.alg === undefined || k.alg === at.header.alg),
		);
		const issuerKey = published === undefined ? undefined : keyFor(at.header.alg, published);
		if (issuerKey === undefined) return token("the token's key");
		if (!signedBy(at, issuerKey)) return token("the token's signature");
		if (at.claims.iss !== options.issuer()) return token("the token's issuer");
		const aud = at.claims.aud;
		const audiences = Array.isArray(aud) ? aud : [aud];
		// RFC 7519 §4.1.3: a string, or a list of strings, one of them this resource's.
		if (audiences.some((a) => typeof a !== "string") || !audiences.includes(options.audience()))
			return token("the token's audience");
		if (typeof at.claims.exp !== "number" || at.claims.exp <= seconds())
			return token("the token has expired");
		if (
			at.claims.nbf !== undefined &&
			(typeof at.claims.nbf !== "number" || at.claims.nbf > seconds())
		)
			return token("the token is not yet valid");
		const jkt = (at.claims.cnf as { readonly jkt?: unknown } | undefined)?.jkt;
		if (typeof jkt !== "string") return token("the token is bound to no key");
		const header = req.headers.dpop;
		if (header === undefined) return proofRefused("no DPoP proof");
		// Repeated headers arrive joined by a comma, which no JWS holds: more than one proof.
		if (Array.isArray(header) || header.includes(",")) return proofRefused("more than one proof");
		const proof = jwsOf(header);
		if (proof === undefined) return proofRefused("the proof is no JWS");
		if (typOf(proof.header.typ) !== "dpop+jwt") return proofRefused("the proof's typ");
		const jwk = proof.header.jwk as Jwk | undefined;
		if (typeof jwk !== "object" || jwk === null) return proofRefused("the proof names no key");
		if ("d" in jwk || "p" in jwk || "q" in jwk) return proofRefused("the proof's key is private");
		const proofKey = keyFor(proof.header.alg, jwk);
		if (proofKey === undefined) return proofRefused("the proof's algorithm");
		if (!signedBy(proof, proofKey)) return proofRefused("the proof's signature");
		const claims = proof.claims;
		if (typeof claims.jti !== "string" || claims.jti === "") return proofRefused("the proof's jti");
		if (claims.htm !== req.method) return proofRefused("the proof's htm");
		if (typeof claims.htu !== "string" || htuOf(claims.htu) !== htuOf(target.toString()))
			return proofRefused("the proof's htu");
		if (typeof claims.iat !== "number" || Math.abs(claims.iat - seconds()) > proofWindowS)
			return proofRefused("the proof's iat");
		if (claims.ath !== b64u(sha256(value))) return proofRefused("the proof's ath");
		if (thumbprintOf(jwk) !== jkt) return token("the proof is not of the token's key");
		if (spent.has(claims.jti)) return proofRefused("the proof was used already");
		spent.add(claims.jti);
		return { sub: at.claims.sub, scope: at.claims.scope };
	};
	const isRefused = (checked: Refused | Record<string, unknown>): checked is Refused =>
		typeof checked.status === "number";
	const answer = async (req: IncomingMessage, res: ServerResponse) => {
		const echoed = req.headers["x-fapi-interaction-id"];
		const interaction = typeof echoed === "string" ? { "x-fapi-interaction-id": echoed } : {};
		const checked = await check(req);
		if (!isRefused(checked)) {
			// Node writes the Date header itself, as the suite asks.
			res
				.writeHead(200, { ...interaction, "content-type": "application/json" })
				.end(JSON.stringify(checked));
			return;
		}
		refusals.push(checked);
		const { status, error, description } = checked;
		const challenge =
			error === undefined
				? `DPoP algs="${algs}"`
				: `DPoP error="${error}", error_description="${description}", algs="${algs}"`;
		res.writeHead(status, {
			...interaction,
			...(status === 401 && { "www-authenticate": challenge }),
			...(error !== undefined && { "content-type": "application/json" }),
		});
		res.end(
			error === undefined ? undefined : JSON.stringify({ error, error_description: description }),
		);
	};
	const server = createServer((req, res) => {
		answer(req, res).catch((error) => {
			if (!res.headersSent)
				res.writeHead(500, { "content-type": "text/plain; charset=utf-8" }).end(String(error));
		});
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", reject);
			resolve();
		});
	});
	const port = (server.address() as AddressInfo).port;
	const closed = () => new Promise<void>((resolve) => server.close(() => resolve()));
	let edge: Front;
	try {
		const tls = await selfSigned(options.host, join(options.dir, "resource-tls"));
		edge = await startFront({
			upstream: () => `http://127.0.0.1:${port}`,
			publicHost: options.host,
			listen: options.listen,
			tls,
		});
		origin = edge.origin;
		return {
			url: `${origin}${path}`,
			certificate: tls.cert,
			refused: () => refusals,
			stop: async () => {
				const problems = await stopAll([closed, () => edge.stop()]);
				if (problems.length > 0) throw new AggregateError(problems, "the resource did not stop");
			},
		};
	} catch (error) {
		await closed();
		throw error;
	}
}
