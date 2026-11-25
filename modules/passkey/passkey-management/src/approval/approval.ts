import { createHash } from "node:crypto";
import type { Approvals } from "@mod/approvals";
import { Unavailable } from "@mod/kernel";
import type { Passkeys } from "@mod/passkeys";
import type { Users } from "@mod/users";
import { accountOf } from "../account.ts";
import type { Created, CreationAsk } from "../creation/creation.ts";
import type { Screen } from "../sealed/sealed.ts";

/** An approval's start answered: its statement; or refused, its reason for the log alone. */
export type Started =
	| { readonly kind: "statement"; readonly statement: string }
	| { readonly kind: "refused"; readonly reason: string };

/** An approval's finish answered: the completion sealed to the screen; or refused, its reason for the log alone. */
export type Finished =
	| { readonly kind: "completed"; readonly enc: string; readonly ct: string }
	| { readonly kind: "refused"; readonly reason: string };

export interface ApprovalParts {
	readonly approvals: Pick<Approvals, "issue" | "use" | "passkeyAddOf" | "completePasskeyAdd">;
	readonly passkeys: Pick<Passkeys, "publicKeyOf">;
	readonly users: Pick<Users, "contactsOf">;
	readonly create: (ask: CreationAsk) => Promise<Created>;
	/** The deployment's name an account no address names shows. */
	readonly deployment: string;
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const refused = (reason: string) => ({ kind: "refused", reason }) as const;
const unavailable = (): never => {
	throw new Unavailable("passkey-management");
};

/**
 * A passkey-add's approval (§3.13's registration, step 1, and step 2): `start` signs the passkey-add
 * for the screen; `finish` uses it by the approving key's assertion and answers the completion
 * carrying the creation it bases, made for the subject that key holds.
 */
export function approvalOver(p: ApprovalParts) {
	async function start(q: {
		readonly purpose: "passkey-add" | "passkey-manage";
		readonly screen: Screen;
		readonly by: string;
	}): Promise<Started> {
		// A passkey-manage is signed by no purpose here yet.
		if (q.purpose !== "passkey-add") return refused("purpose");
		const issued = await p.approvals.issue({
			purpose: "passkey-add",
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

	async function finish(q: {
		readonly statement: string;
		readonly assertion: string;
	}): Promise<Finished> {
		const hash = sha256(q.statement);
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
		if ((await p.passkeys.publicKeyOf(credential))?.registration !== registration)
			return refused("approver");
		const added = await p.approvals.passkeyAddOf(hash);
		if (!added) return refused("expired");
		const shown = accountOf(await p.users.contactsOf(subject), p.deployment, subject);
		const created = await p.create({
			subject,
			...shown,
			basis: "passkey-add",
			evidence: hash,
			screen: added.screen,
			since: approval.issuedAt,
		});
		if (created.kind === "refused" && created.reason === "items") return refused("items");
		if (created.kind === "refused" && created.reason === "revoked") return refused("revoked");
		// Counted out, busy or withdrawn: nothing kept, asked again later.
		if (created.kind === "refused") return unavailable();
		return kept(hash, q.assertion, created.statement);
	}

	return { start, finish };
}
