import type { RelyingParty } from "../roles/rp.ts";
import { entry } from "./pattern.ts";

/**
 * The client the operator registers for a relying party: private_key_jwt by its key, its redirect URI,
 * the grants and scope it is allowed, and DPoP's binding required. Each section by its owner's `./testing`.
 */
export async function registered(
	rp: RelyingParty,
	grants: readonly string[] = ["authorization_code"],
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
