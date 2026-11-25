import {
	createHash,
	createPublicKey,
	generateKeyPairSync,
	type KeyObject,
	randomBytes,
	randomUUID,
	sign,
	verify,
} from "node:crypto";
import { typs } from "@mod/sdk-core-wire";
import type { Sent } from "../../src/contract.ts";

const b64u = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");
const sha256 = (text: string) => createHash("sha256").update(text).digest();
const now = () => Math.floor(Date.now() / 1000);

/** An ES256 compact JWS over the header and claims. */
export function es256(key: KeyObject, header: object, claims: object): string {
	const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
	const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
	return `${input}.${b64u(signature)}`;
}

/** A P-256 key pair: its private half, and its public JWK's members. */
export function p256() {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const { x, y } = pair.publicKey.export({ format: "jwk" });
	return { privateKey: pair.privateKey, jwk: { kty: "EC", crv: "P-256", x: x ?? "", y: y ?? "" } };
}

/** RFC 7638's thumbprint of a P-256 public key, base64url. */
export const thumbprint = (jwk: { x: string; y: string }) =>
	b64u(sha256(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`));

/** A JWT's claims, read without checking anything. */
export const claimsOf = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8"));

/** The ID tokens' algorithms the relying party takes, each by its key's type. */
const algorithms = { ES256: "EC", RS256: "RSA", EdDSA: "OKP" } as const;

/** A key the provider signs ID tokens with, as its JWKS publishes it. */
export type ProviderKey = Record<string, unknown> & {
	readonly kid?: string;
	readonly kty?: string;
	readonly alg?: string;
};

/** Where the relying party talks to the provider: its issuer and the token endpoint's and PAR's URLs. */
export interface Provider {
	readonly issuer: string;
	readonly tokenUrl: string;
	readonly parUrl: string;
}

/** An authorization the relying party started: what it keeps in its session and the JAR it signed. */
export interface Started {
	readonly state: string;
	readonly nonce: string;
	readonly verifier: string;
	readonly jar: string;
}

/**
 * A relying party with a private_key_jwt client key and a DPoP key, as the harness's tests play it: it
 * signs JARs, client assertions and DPoP proofs, and checks what it is handed as its obligations say
 * (R2 the ID token's `nonce`, R3 the callback's `state`, R15 `c_hash`).
 */
export function relyingParty(provider: Provider, clientId: string, redirectUri: string) {
	const client = p256();
	const kid = `${clientId}-key`;
	const dpopKey = p256();
	const dpopJkt = thumbprint(dpopKey.jwk);
	const assertion = () =>
		es256(
			client.privateKey,
			{ alg: "ES256", typ: typs.clientAssertion, kid },
			{
				iss: clientId,
				sub: clientId,
				aud: provider.issuer,
				jti: randomUUID(),
				iat: now(),
				exp: now() + 60,
			},
		);
	const authenticated = {
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: assertion,
	};
	const proof = (htm: string, htu: string, nonce?: string, accessToken?: string) =>
		es256(
			dpopKey.privateKey,
			{ alg: "ES256", typ: typs.dpop, jwk: dpopKey.jwk },
			{
				jti: randomUUID(),
				htm,
				htu,
				iat: now(),
				...(nonce !== undefined && { nonce }),
				...(accessToken !== undefined && { ath: b64u(sha256(accessToken)) }),
			},
		);
	return {
		clientId,
		redirectUri,
		/** The public key the operator registers for the client. */
		publicKey: { ...client.jwk, kid, alg: "ES256", use: "sig" },
		dpopJkt,
		/** A new authorization: its state, nonce and PKCE verifier, and the JAR naming them. */
		authorization: (items: Record<string, unknown> = {}): Started => {
			const state = b64u(randomBytes(16));
			const nonce = b64u(randomBytes(16));
			const verifier = b64u(randomBytes(32));
			const jar = es256(
				client.privateKey,
				{ alg: "ES256", typ: typs.jar, kid },
				{
					iss: clientId,
					aud: provider.issuer,
					iat: now(),
					exp: now() + 300,
					jti: randomUUID(),
					client_id: clientId,
					redirect_uri: redirectUri,
					response_type: "code",
					response_mode: "form_post",
					state,
					scope: "openid",
					nonce,
					code_challenge: b64u(sha256(verifier)),
					code_challenge_method: "S256",
					dpop_jkt: dpopJkt,
					...items,
				},
			);
			return { state, nonce, verifier, jar };
		},
		/** The JAR pushed (PAR, RFC 9126), authenticated by an assertion. */
		par: (jar: string): Sent => ({
			path: "/oauth/par",
			body: {
				request: jar,
				client_assertion_type: authenticated.client_assertion_type,
				client_assertion: assertion(),
			},
		}),
		/** The code's exchange, with the verifier, an assertion and a DPoP proof under `nonce` if the provider asked one. */
		token: (code: string, verifier: string, nonce?: string): Sent => ({
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code,
				redirect_uri: redirectUri,
				code_verifier: verifier,
				client_assertion_type: authenticated.client_assertion_type,
				client_assertion: assertion(),
			},
			headers: { dpop: proof("POST", provider.tokenUrl, nonce) },
		}),
		/** A refresh, with an assertion and a DPoP proof. */
		refresh: (refreshToken: string, nonce?: string): Sent => ({
			path: "/oauth/token",
			body: {
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_assertion_type: authenticated.client_assertion_type,
				client_assertion: assertion(),
			},
			headers: { dpop: proof("POST", provider.tokenUrl, nonce) },
		}),
		/** A DPoP proof of this client's key, for a request of its own making. */
		proof,
		/** A client assertion, for a request of its own making. */
		assertion,
		/**
		 * The obligations' checks on an ID token handed for the authorization started (R2, R15), beside
		 * its signature by one of the provider's keys, issuer, audience and expiry: each failing one named.
		 */
		idTokenFaults: (
			idToken: string,
			started: Started,
			code: string,
			keys: readonly ProviderKey[],
		) => {
			const parts = idToken.split(".");
			if (parts.length !== 3) return ["form"];
			const [head = "", body = "", signature = ""] = parts;
			const header = JSON.parse(Buffer.from(head, "base64url").toString("utf8"));
			const claims = claimsOf(idToken);
			const key = keys.find((k) => k.kid === header.kid);
			// The algorithms an RP takes, each of its key's type, and the key's own where it names one.
			const fits =
				key !== undefined &&
				Object.hasOwn(algorithms, header.alg) &&
				algorithms[header.alg as keyof typeof algorithms] === key.kty &&
				(key.alg === undefined || key.alg === header.alg);
			const signed =
				fits &&
				verify(
					header.alg === "EdDSA" ? null : "sha256",
					Buffer.from(`${head}.${body}`),
					{
						key: createPublicKey({ key: key as JsonWebKey, format: "jwk" }),
						dsaEncoding: "ieee-p1363",
					},
					Buffer.from(signature, "base64url"),
				);
			const digest = sha256(code);
			const faults = [
				!signed && "signature",
				claims.iss !== provider.issuer && "iss",
				claims.aud !== clientId &&
					!(Array.isArray(claims.aud) && claims.aud.includes(clientId)) &&
					"aud",
				!(typeof claims.exp === "number" && claims.exp > now()) && "exp",
				claims.nonce !== started.nonce && "nonce",
				claims.c_hash !== b64u(digest.subarray(0, digest.length / 2)) && "c_hash",
			];
			return faults.filter((fault): fault is string => fault !== false);
		},
		/** R3: a callback taken only at its redirect URI, for the state this session started with; each failing check named. */
		callbackFaults: (
			callback: { readonly state: string; readonly redirectUri: string },
			started: Started,
		) =>
			[
				callback.redirectUri !== redirectUri && "redirect_uri",
				callback.state !== started.state && "state",
			].filter((fault): fault is string => fault !== false),
	};
}

export type RelyingParty = ReturnType<typeof relyingParty>;
