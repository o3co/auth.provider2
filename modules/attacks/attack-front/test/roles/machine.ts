import { randomUUID } from "node:crypto";
import { typs } from "@mod/sdk-core-wire";
import type { Sent } from "../../src/contract.ts";
import { es256, p256, thumbprint } from "./rp.ts";

const now = () => Math.floor(Date.now() / 1000);

/**
 * A machine client (client_credentials, RFC 6749 §4.4): one key, written in its signed record, that
 * signs its assertion and makes its DPoP proof, as the provider binds the token to that very key.
 */
export function machineClient(
	id: string,
	provider: { readonly issuer: string; readonly tokenUrl: string },
) {
	const key = p256();
	const kid = `${id}-key`;
	/** An assertion for an audience, the provider's unless said (a client of two ASs signs for each). */
	const assertion = (aud = provider.issuer) =>
		es256(
			key.privateKey,
			{ alg: "ES256", typ: typs.clientAssertion, kid },
			{ iss: id, sub: id, aud, jti: randomUUID(), iat: now(), exp: now() + 60 },
		);
	const proof = (nonce?: string) =>
		es256(
			key.privateKey,
			{ alg: "ES256", typ: typs.dpop, jwk: key.jwk },
			{
				jti: randomUUID(),
				htm: "POST",
				htu: provider.tokenUrl,
				iat: now(),
				...(nonce !== undefined && { nonce }),
			},
		);
	return {
		id,
		publicKey: { ...key.jwk, kid, alg: "ES256", use: "sig" },
		jkt: thumbprint(key.jwk),
		assertion,
		proof,
		/** Its token request: the scope and resource asked, an assertion, a proof under `nonce` if the AS asked one. */
		request: (scope: string, resource: string, nonce?: string): Sent => ({
			path: "/oauth/token",
			body: {
				grant_type: "client_credentials",
				scope,
				resource,
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: assertion(),
			},
			headers: { dpop: proof(nonce) },
		}),
	};
}

export type MachineClient = ReturnType<typeof machineClient>;
