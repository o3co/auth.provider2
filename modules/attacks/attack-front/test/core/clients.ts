import type { RelyingParty } from "../roles/rp.ts";
import { entry } from "./pattern.ts";

/**
 * The client the operator registers for a relying party: private_key_jwt by its key, its redirect URI,
 * the grants and scope it is allowed, and DPoP's binding required. Each section by its owner's `./testing`.
 */
export async function registered(
	rp: RelyingParty,
	grants: readonly string[] = ["authorization_code", "refresh_token"],
) {
	const { clientKeysFor } = await entry("@mod/client-assertion", "./testing");
	const { redirectsFor } = await entry("@mod/redirect-uris", "./testing");
	const { allowancesFor } = await entry("@mod/client-allowance", "./testing");
	return {
		id: rp.clientId,
		kind: "confidential",
		method: "private_key_jwt",
		sections: {
			...clientKeysFor([rp.publicKey]),
			...redirectsFor([rp.redirectUri]),
			...allowancesFor({ grants, scopes: ["openid"] }),
			"sender-binding": { required: true },
		},
	};
}

/**
 * A machine client of a signed registry version: private_key_jwt by its one key, allowed the client
 * credentials grant for itself at each audience given, with its scopes.
 */
export async function signedMachine(
	id: string,
	publicKey: Record<string, unknown>,
	self: readonly { readonly audience: string; readonly scopes: readonly string[] }[],
	version = 1,
) {
	const { clientKeysFor } = await entry("@mod/client-assertion", "./testing");
	const { allowancesFor } = await entry("@mod/client-allowance", "./testing");
	return {
		id,
		kind: "confidential",
		method: "private_key_jwt",
		sections: {
			...allowancesFor({ grants: ["client_credentials"], self }),
			...clientKeysFor([publicKey]),
		},
		version,
	};
}

/** A key set's URL in place of written keys: client-assertion's section, as an operator writes it. */
const atUri = async (jwksUri: string) => {
	const { clientKeys } = await entry("@mod/client-assertion");
	return { [clientKeys.name]: { "jwks-uri": jwksUri } };
};

/** The client the operator registers for a relying party (`registered`), its keys at a key set's URL instead. */
export async function uriRelyingParty(rp: RelyingParty, jwksUri: string) {
	const client = await registered(rp);
	const { clientKeys } = await entry("@mod/client-assertion");
	const { [clientKeys.name]: _written, ...sections } = client.sections;
	return { ...client, sections: { ...sections, ...(await atUri(jwksUri)) } };
}

/** A machine client of a signed registry version (`signedMachine`), naming a key set's URL instead of its key. */
export async function signedUriMachine(
	id: string,
	jwksUri: string,
	self: readonly { readonly audience: string; readonly scopes: readonly string[] }[],
	version = 1,
) {
	const { allowancesFor } = await entry("@mod/client-allowance", "./testing");
	return {
		id,
		kind: "confidential",
		method: "private_key_jwt",
		sections: {
			...allowancesFor({ grants: ["client_credentials"], self }),
			...(await atUri(jwksUri)),
		},
		version,
	};
}

/**
 * A machine client the operator registers, its keys at a key set's URL, allowed the client credentials
 * grant (no ceiling of its own: a registered client writes none).
 */
export async function uriMachine(id: string, jwksUri: string) {
	const { allowancesFor } = await entry("@mod/client-allowance", "./testing");
	return {
		id,
		kind: "confidential",
		method: "private_key_jwt",
		sections: { ...allowancesFor({ grants: ["client_credentials"] }), ...(await atUri(jwksUri)) },
	};
}
