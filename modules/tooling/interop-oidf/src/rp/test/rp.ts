/**
 * The harness's relying party: a private_key_jwt client with its own DPoP key per authorization, as a
 * conforming client of nextgen sends its requests. It signs JARs, client assertions and DPoP proofs, and
 * makes the record the operator registers for it.
 */
import {
	createECDH,
	createHash,
	generateKeyPairSync,
	type KeyObject,
	randomBytes,
	randomUUID,
	sign,
} from "node:crypto";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientKeysFor } from "@mod/client-assertion/testing";
import { redirectsFor } from "@mod/redirect-uris/testing";
import { typs } from "@mod/sdk-core-wire";
import type { Answered, Asking } from "../../scene/test/ask.ts";

const b64u = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");
const sha256 = (text: string) => createHash("sha256").update(text).digest();
const seconds = () => Math.floor(Date.now() / 1000);

/** An ES256 compact JWS over the header and claims. */
export function es256(key: KeyObject, header: object, claims: object): string {
	const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
	const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
	return `${input}.${b64u(signature)}`;
}

/** A P-256 key pair: its private half, and its public JWK's members. */
function p256() {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const { x, y } = pair.publicKey.export({ format: "jwk" });
	return { privateKey: pair.privateKey, jwk: { kty: "EC", crv: "P-256", x: x ?? "", y: y ?? "" } };
}

/** RFC 7638's thumbprint of a P-256 public key, base64url. */
export const thumbprint = (jwk: { readonly x: string; readonly y: string }) =>
	b64u(sha256(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`));

/** A DPoP proof of a key: the method, the URL, the nonce the server gave if any, the access token it goes with. */
export type Proof = (htm: string, htu: string, nonce?: string, accessToken?: string) => string;

/** A DPoP key's thumbprint and its proofs (RFC 9449). */
export function dpopKey(): { readonly jkt: string; readonly proof: Proof } {
	const key = p256();
	return {
		jkt: thumbprint(key.jwk),
		proof: (htm, htu, nonce, accessToken) =>
			es256(
				key.privateKey,
				{ alg: "ES256", typ: typs.dpop, jwk: key.jwk },
				{
					jti: randomUUID(),
					htm,
					htu,
					iat: seconds(),
					...(nonce !== undefined && { nonce }),
					...(accessToken !== undefined && { ath: b64u(sha256(accessToken)) }),
				},
			),
	};
}

/** Where the relying party reaches the provider. */
export interface Provider {
	readonly issuer: string;
	readonly parUrl: string;
	readonly tokenUrl: string;
}

/** An authorization started: what the session keeps, the JAR naming it, and its own DPoP key. */
export interface Started {
	readonly state: string;
	readonly nonce: string;
	readonly verifier: string;
	readonly jar: string;
	readonly dpopJkt: string;
	readonly proof: Proof;
}

/** A form a request carries, and its headers. */
export interface Sending {
	readonly form: Readonly<Record<string, string>>;
	readonly headers?: Readonly<Record<string, string>>;
}

/** A request sent, and whether a DPoP nonce was asked before its answer (it was then sent again under it). */
export interface Sent {
	readonly answer: Answered;
	readonly nonceAsked: boolean;
}

/**
 * Sends a request the relying party built, once more under the DPoP nonce where the provider asks one
 * (`use_dpop_nonce` with `DPoP-Nonce`, RFC 9449 §8), as a client does.
 */
export async function send(
	ask: (path: string, init: Asking) => Promise<Answered>,
	path: string,
	built: (nonce?: string) => Sending,
): Promise<Sent> {
	const answer = await ask(path, { method: "POST", ...built() });
	const nonce = answer.headers["dpop-nonce"];
	if (answer.status === 400 && answer.json.error === "use_dpop_nonce" && typeof nonce === "string")
		return { answer: await ask(path, { method: "POST", ...built(nonce) }), nonceAsked: true };
	return { answer, nonceAsked: false };
}

/** A login screen's two keys as a start carries them: an encryption key (raw P-256) and a signing key's x and y, base64url. */
export function screenKeys() {
	const enc = createECDH("prime256v1");
	enc.generateKeys();
	const { x, y } = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({
		format: "jwk",
	});
	return { eEnc: b64u(enc.getPublicKey()), eSigX: x ?? "", eSigY: y ?? "" };
}

/** The claims a JAR carries, as a conforming client of nextgen writes them, but those `change` replaces or `drop` names. */
export interface JarChange {
	readonly items?: Readonly<Record<string, unknown>>;
	readonly drop?: readonly string[];
	/** The header's `typ`, its own unless given; `null` leaves it out. */
	readonly typ?: string | null;
}

/**
 * A relying party, its client id and its redirect URI; `provider` is read when it signs, so its key can
 * be registered before the provider (the scene) starts.
 */
export function relyingParty(clientId: string, redirectUri: string, provider: () => Provider) {
	const client = p256();
	const kid = `${clientId}-key`;
	const assertion = () =>
		es256(
			client.privateKey,
			{ alg: "ES256", typ: typs.clientAssertion, kid },
			{
				iss: clientId,
				sub: clientId,
				aud: provider().issuer,
				jti: randomUUID(),
				iat: seconds(),
				exp: seconds() + 60,
			},
		);
	const authenticated = () => ({
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: assertion(),
	});
	const publicKey = { ...client.jwk, kid, alg: "ES256", use: "sig" };
	return {
		clientId,
		redirectUri,
		publicKey,
		/** The record the operator registers for it: private_key_jwt by its key, its redirect URI, the code and refresh grants, DPoP required. */
		registered: () => ({
			id: clientId,
			kind: "confidential",
			method: "private_key_jwt",
			sections: {
				...clientKeysFor([publicKey]),
				...redirectsFor([redirectUri]),
				...allowancesFor({ grants: ["authorization_code", "refresh_token"], scopes: ["openid"] }),
				"sender-binding": { required: true },
			},
		}),
		/**
		 * A new authorization: its state, nonce and PKCE verifier, and the JAR naming them as nextgen asks
		 * (`response_mode=form_post`, `jti`, `nbf`, a short `exp`, `dpop_jkt`), changed as `change` says.
		 */
		authorization: (change: JarChange = {}): Started => {
			const state = b64u(randomBytes(16));
			const nonce = b64u(randomBytes(16));
			const verifier = b64u(randomBytes(32));
			const dpop = dpopKey();
			const claims: Record<string, unknown> = {
				iss: clientId,
				aud: provider().issuer,
				iat: seconds(),
				nbf: seconds(),
				exp: seconds() + 60,
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
				dpop_jkt: dpop.jkt,
				...change.items,
			};
			for (const name of change.drop ?? []) delete claims[name];
			const typ = change.typ === undefined ? typs.jar : change.typ;
			const jar = es256(
				client.privateKey,
				{ alg: "ES256", kid, ...(typ === null ? {} : { typ }) },
				claims,
			);
			return { state, nonce, verifier, jar, dpopJkt: dpop.jkt, proof: dpop.proof };
		},
		/**
		 * The JAR pushed (PAR, RFC 9126), authenticated by an assertion; with a DPoP proof of the session's
		 * key under `nonce` where proved (or of `by`, another key, for a test of the proof's own check).
		 */
		par: (
			started: Started,
			proving: { readonly nonce?: string | undefined; readonly by?: Proof } | false = false,
		): Sending => ({
			form: { request: started.jar, ...authenticated() },
			...(proving === false
				? {}
				: {
						headers: {
							dpop: (proving.by ?? started.proof)("POST", provider().parUrl, proving.nonce),
						},
					}),
		}),
		/** A login's start as a screen sends it: the client, the JAR by value or a PAR's `request_uri` (or neither), the screen's keys. */
		start: (
			by: { readonly request?: string; readonly requestUri?: string },
			keys: ReturnType<typeof screenKeys> = screenKeys(),
		) => ({ clientId, ...by, ...keys }),
		/** The session's code exchange: its verifier, an assertion, its DPoP proof under `nonce` if the provider asked one. */
		token: (started: Started, code: string, nonce?: string): Sending => ({
			form: {
				grant_type: "authorization_code",
				code,
				redirect_uri: redirectUri,
				code_verifier: started.verifier,
				...authenticated(),
			},
			headers: { dpop: started.proof("POST", provider().tokenUrl, nonce) },
		}),
		/** A refresh, with an assertion and the session's DPoP proof under `nonce`. */
		refresh: (started: Started, refreshToken: string, nonce?: string): Sending => ({
			form: { grant_type: "refresh_token", refresh_token: refreshToken, ...authenticated() },
			headers: { dpop: started.proof("POST", provider().tokenUrl, nonce) },
		}),
		/** A client assertion, for a request of its own making. */
		assertion,
	};
}

export type RelyingParty = ReturnType<typeof relyingParty>;
