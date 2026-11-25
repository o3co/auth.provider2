import { hpke } from "@mod/sdk-core-wire";

/** A completion padded to the bucket its longest credential ID's bytes choose; none where it does not fit, never sealed. */
export const paddedFor = (jws: string, ids: readonly string[]): string | undefined =>
	hpke.paddedCompletion(jws, Math.max(0, ...ids.map((id) => Buffer.from(id, "base64url").length)));
