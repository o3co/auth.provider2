import type { AccessTokenIssuance, IssuanceRequest, Issued, IssueLimits } from "../contract.ts";

/** Issues as `prepare` then `sign`: signed at once, recorded nowhere, for a test that needs no bundle. */
export async function issueAtOnce(
	t: Pick<AccessTokenIssuance, "prepare" | "sign">,
	request: IssuanceRequest,
	limits?: IssueLimits,
): Promise<Issued> {
	const prepared = await t.prepare(request, limits);
	return prepared.kind === "refused" ? prepared : t.sign(prepared);
}
