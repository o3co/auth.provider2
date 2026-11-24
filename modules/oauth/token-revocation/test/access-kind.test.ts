import type { Client } from "@mod/clients";
import type { Revocation, Tokens } from "@mod/tokens";
import { expect, it } from "vitest";
import { accessKind } from "../src/revocation.ts";

/** Tokens issuing every token to "app", revoking as `revoked` says. */
const tokensRevoking = (revoked: Revocation): Tokens =>
	({
		issuedToOf: async () => ({ kind: "issued", issuedTo: "app" }),
		revokeAccess: async () => revoked,
	}) as Partial<Tokens> as Tokens;
const app = { id: "app" } as Client;

it("says written only for a revocation tokens wrote, and unknown for a token that no longer verifies", async () => {
	const answers = await Promise.all(
		(["revoked", "invalid", "unsupported"] as const).map((kind) =>
			accessKind(tokensRevoking({ kind })).revoke("t", app),
		),
	);
	expect(answers).toEqual(["written", "unknown", "unsupported"]);
});
