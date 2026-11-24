import type { Client } from "@mod/clients";
import { extensionPoint } from "@mod/kernel";

/** "written": this call wrote the revocation; "done": nothing left to do, as for another client's token. */
export type Revoked = "done" | "unknown" | "unsupported" | "written";

/** A kind of token its owner revokes, tried by its hint (RFC 7009 §2.1). */
export interface RevocableKind {
	readonly hint: string;
	revoke(token: string, client: Client): Promise<Revoked>;
}

export const revocableKinds = extensionPoint<RevocableKind>("token-revocation.revocable-kinds", {
	multiplicity: "keyed",
	keyOf: (kind) => kind.hint,
});
