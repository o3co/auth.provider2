import { createHash } from "node:crypto";
import type { Approvals, Screen } from "@mod/approvals";
import { Unavailable } from "@mod/kernel";
import type { Passkeys } from "@mod/passkeys";
import type { Users } from "@mod/users";
import { passkeyJwk } from "@mod/webauthn";
import { accountOf } from "../account.ts";
import type { Created, CreationAsk } from "../creation/creation.ts";

/** An approval's start answered: its statement; or refused, its reason for the log alone. */
export type Started =
	| { readonly kind: "statement"; readonly statement: string }
	| { readonly kind: "refused"; readonly reason: string };

/** An approval's finish answered: the completion sealed to the screen; or refused, its reason for the log alone. */
export type Finished =
	| { readonly kind: "completed"; readonly enc: string; readonly ct: string }
	| { readonly kind: "refused"; readonly reason: string };

export interface ApprovalParts {
	readonly approvals: Pick<
		Approvals,
		"issue" | "use" | "passkeyAddOf" | "completePasskeyAdd" | "completePasskeyManage"
	>;
	readonly passkeys: Pick<Passkeys, "publicKeyOf">;
	readonly users: Pick<Users, "contactsOf">;
	readonly create: (ask: CreationAsk) => Promise<Created>;
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
/** A statement's purpose as its payload names it, unverified; none for one that does not read. */
const purposeOf = (statement: string): unknown => {
	try {
		return JSON.parse(Buffer.from(statement.split(".")[1] ?? "", "base64url").toString("utf8"))
			?.purpose;
	} catch {
		return undefined;
	}
};
const refused = (reason: string) => ({ kind: "refused", reason }) as const;
const unavailable = (): never => {
	throw new Unavailable("passkey-management");
};

/**
 * A passkey-add's or a passkey-manage's approval: `start` signs it for the screen; `finish` uses it by
 * the approving key's assertion and answers a passkey-add's completion carrying the creation it bases
 * (§3.13's registration, steps 1 and 2), or a passkey-manage's list of that key's subject's keys.
 */
export function approvalOver(p: ApprovalParts) {
	async function start(q: {
		readonly purpose: "passkey-add" | "passkey-manage";
		readonly screen: Screen;
		readonly by: string;
	}): Promise<Started> {
		const issued = await p.approvals.issue({
			purpose: q.purpose,
			items: {},
			screen: q.screen,
			by: q.by,
		});
		if (issued.kind === "issued") return { kind: "statement", statement: issued.statement };
		// Counted out, busy or withdrawn: nothing kept, asked again later.
		return issued.reason === "items" ? refused("screen") : unavailable();
	}

	/** The completion approvals keeps: one kept is answered, a refusal of no passkey-add stops here. */
	async function kept(hash: string, assertion: string, creation?: string): Promise<Finished> {
		const done = await p.approvals.completePasskeyAdd({
			hash,
			assertion,
			...(creation === undefined ? {} : { creation }),
		});
		if (done.kind === "completed") return { kind: "completed", enc: done.enc, ct: done.ct };
		return done.reason === "withdrawn" ? unavailable() : refused(done.reason);
	}

	/** A passkey-manage's: the list of its subject's keys, by the approving key as it was when it approved. */
	async function manage(
		hash: string,
		q: { readonly statement: string; readonly assertion: string },
	) {
		const answered = async (make?: true): Promise<Finished> => {
			const done = await p.approvals.completePasskeyManage({
				hash,
				assertion: q.assertion,
				...(make ? { make } : {}),
			});
			if (done.kind === "completed") return { kind: "completed", enc: done.enc, ct: done.ct };
			return done.reason === "withdrawn" ? unavailable() : refused(done.reason);
		};
		// A completion kept is answered as kept, whatever has lapsed since; with none kept, every finish
		// is used and its approving key checked again before one is made.
		const before = await answered();
		if (before.kind === "completed" || (before.reason !== "unused" && before.reason !== "unknown"))
			return before;
		const used = await p.approvals.use({ statement: q.statement, assertion: q.assertion });
		if (used.kind === "refused") return refused(used.reason);
		const { purpose, credential, registration } = used.approval;
		if (purpose !== "passkey-manage" || !credential || !registration) return refused("purpose");
		if ((await p.passkeys.publicKeyOf(credential))?.registration !== registration)
			return refused("approver");
		return answered(true);
	}

	async function finish(q: {
		readonly statement: string;
		readonly assertion: string;
	}): Promise<Finished> {
		const hash = sha256(q.statement);
		// Its purpose as signed picks the path alone: approvals checks the statement itself.
		if (purposeOf(q.statement) === "passkey-manage") return manage(hash, q);
		// A completion kept is answered as kept, whatever has lapsed since; none of another purpose is used.
		const before = await kept(hash, q.assertion);
		if (before.kind === "completed" || before.reason !== "unknown") return before;
		const used = await p.approvals.use({ statement: q.statement, assertion: q.assertion });
		if (used.kind === "refused") return refused(used.reason);
		const approval = used.approval;
		// An authorization's statement and assertion sent here base no creation.
		if (approval.purpose !== "passkey-add") return refused("purpose");
		const { subject, credential, registration } = approval;
		if (!subject || !credential || !registration) return refused("unknown");
		// The approving key, as it was when it approved: one removed since, or registered again, bases none.
		const approving = await p.passkeys.publicKeyOf(credential);
		if (approving?.registration !== registration) return refused("approver");
		// Named in the creation (V30): the key change's parent, the screen's own key. An RS256 key approves
		// no passkey-add in 0.1.0: no binding against duplicate-signature key selection is shown for it.
		const approverKey = passkeyJwk(approving.publicKey)?.jwk;
		if (!approverKey) return refused("approver");
		if (approverKey.kty === "RSA") return refused("approver-algorithm");
		const added = await p.approvals.passkeyAddOf(hash);
		if (!added) return refused("expired");
		const shown = accountOf(await p.users.contactsOf(subject));
		const created = await p.create({
			subject,
			...shown,
			basis: "passkey-add",
			approverKey,
			evidence: hash,
			screen: added.screen,
			since: approval.issuedAt,
		});
		if (created.kind === "refused" && created.reason === "items") return refused("items");
		if (created.kind === "refused" && created.reason === "revoked") return refused("revoked");
		if (created.kind === "refused" && created.reason === "full") return refused("full");
		// Counted out, busy or withdrawn: nothing kept, asked again later.
		if (created.kind === "refused") return unavailable();
		return kept(hash, q.assertion, created.statement);
	}

	return { start, finish };
}
