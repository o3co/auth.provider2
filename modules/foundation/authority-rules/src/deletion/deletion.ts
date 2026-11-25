import { continuations } from "@mod/continuation-wire";
import { canonicalText } from "@mod/sdk-core-wire";
import {
	assertedBy,
	type Checks,
	type Context,
	continuationOf,
	statementOf,
	statements,
} from "../evidence/evidence.ts";
import { type FlowState, own } from "../fold/fold.ts";

/** A key's deletion's evidence, in its one order (V24): the passkey-manage, the approving key's assertion over it, the screen's `delete` continuation. */
const forms = ["statement", "assertion", "continuation"];

/** A `delete` continuation's body, its canonical text of the wire's shape (`continuations.bodies.delete`): the key it names; none otherwise. */
function bodyOf(body: string): { readonly credential_id: string } | undefined {
	try {
		const read = continuations.bodies.delete.safeParse(JSON.parse(body));
		return read.success && canonicalText(read.data) === body ? read.data : undefined;
	} catch {
		return undefined;
	}
}

/** A key's deletion asked: the state just before its record, the caller's checks, its parent, evidence and the credential it names. */
export interface DeletionAsk {
	readonly state: FlowState;
	readonly checks: Checks;
	readonly context: Context;
	readonly parent: string | undefined;
	readonly evidence: readonly { readonly form: string; readonly value: string }[];
	readonly credential: string;
}

/** A deletion read: its passkey-manage, its body, the statement's sid and times, the key it deletes by its registration's id. */
export type Deletion =
	| { readonly refusal: string }
	| {
			readonly statement: string;
			readonly body: string;
			readonly sid: string;
			readonly times: { readonly iat: number; readonly exp: number };
			readonly deleted: string;
	  };

/**
 * A live key a live key's approval deletes (V24): the approving key (`parent`) asserting the
 * passkey-manage; the screen's E_sig over a `delete` continuation naming the record's key; that key
 * live, the approving one or another; a key left after it (the last goes by a reset, a denial or an
 * erasure alone, KP-22). Live is read on the state just before the record. The statement's use and
 * the envelope's digests are the caller's to hold.
 */
export function deletionOf(ask: DeletionAsk): Deletion {
	const { state, checks } = ask;
	const given = ask.evidence.map((e) => e.form);
	if (given.length !== forms.length || given.some((f, at) => f !== forms[at]))
		return {
			refusal:
				"a key's deletion carries its passkey-manage, the approving key's assertion and its continuation in order",
		};
	const [statement = "", asserted = "", sent = ""] = ask.evidence.map((e) => e.value);
	const m = statementOf(statement, statements.passkeyManage, checks, ask.context);
	if (!m) return { refusal: "the passkey-manage is not signed by the writer generation's ring" };
	const continued = continuationOf(sent);
	if (!continued) return { refusal: "the continuation does not read" };
	const body = bodyOf(continued.body);
	if (!body) return { refusal: "the continuation's body names no key to delete" };
	const parent = ask.parent === undefined ? undefined : own(state.keys, ask.parent);
	if (!parent) return { refusal: "the approving key is not live on the flow" };
	if (!assertedBy(asserted, parent, statement, checks, ask.context))
		return { refusal: "the assertion is not the approving key's over the passkey-manage" };
	const input = continuations.of(
		"delete",
		checks.digest(statement),
		continued.seq,
		checks.digest(continued.body),
	);
	if (!checks.verifyEsig(m.e_sig, input, continued.signature))
		return { refusal: "the continuation is not the screen's over the passkey-manage" };
	if (body.credential_id !== ask.credential)
		return { refusal: "the continuation names another key than the record's" };
	const deleted = Object.entries(state.keys).find(([, k]) => k.credential === ask.credential)?.[0];
	if (deleted === undefined) return { refusal: "the key it deletes is not live on the flow" };
	// DelDrop takes exactly the key named: a key is left wherever another is live.
	if (Object.keys(state.keys).length < 2)
		return {
			refusal: "the flow's last key is not deleted: a reset, a denial or an erasure takes it",
		};
	const times = { iat: m.iat, exp: m.exp };
	return { statement, body: continued.body, sid: m.sid, times, deleted };
}
