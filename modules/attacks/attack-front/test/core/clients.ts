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
