import { type CallbackCheck, type CallbackFault, schemas, tokens } from "@mod/transparency-wire";
import { digest, fromBase64url, textOf } from "./bytes.ts";
import { verifyCompact } from "./jws.ts";

const headerOf = (proof: string): unknown => {
	const bytes = fromBase64url(proof.split(".")[0] ?? "");
	const text = bytes && textOf(bytes);
	try {
		return text === undefined ? undefined : JSON.parse(text);
	} catch {
		return undefined;
	}
};

/**
 * R18 (A38): the callback's proof read against the ID token that passed R16. The proof's header is
 * ES256, the callback's `typ` and E_sig's key, which signs it; its key's thumbprint is the ID token's
 * `esig`; its record is the ID token's `apr`; its issuer, client, state and code's hash are the ones
 * expected, as are the ID token's issuer and audience. The faults, the first that holds named, are
 * `tokens.checks.callbackFaults`.
 */
export async function checkCallback(
	check: CallbackCheck,
): Promise<{ readonly ok: true } | { readonly fault: CallbackFault }> {
	const header = schemas.callbackHeader.safeParse(headerOf(check.proof));
	if (!header.success) return { fault: "proof" };
	const { jwk } = header.data;
	const verified = await verifyCompact(check.proof, [{ ...jwk, alg: "ES256" }]);
	const body = verified && schemas.callbackProof.safeParse(verified.payload);
	if (!body?.success) return { fault: "proof" };
	const input = tokens.ecThumbprintInput(jwk);
	if (input === undefined || (await digest(input)) !== check.idToken.esig) return { fault: "key" };
	const { apr } = body.data;
	if (apr.shard !== check.idToken.apr.shard || apr.n !== check.idToken.apr.n)
		return { fault: "apr" };
	const { expected, idToken } = check;
	const fields =
		body.data.iss === expected.iss &&
		idToken.iss === expected.iss &&
		body.data.client_id === expected.client_id &&
		idToken.aud === expected.client_id &&
		body.data.state === expected.state &&
		body.data.code_hash === (await digest(expected.code));
	return fields ? { ok: true } : { fault: "field" };
}
