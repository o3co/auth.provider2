import { continuations } from "@mod/continuation-wire";
import { canonicalText, type PossessionPayload } from "@mod/sdk-core-wire";
import type { AppendRequest } from "@mod/transparency-wire";
import {
	type ClientAt,
	evidenceRead,
	evidenceTimely,
	startOf,
	tokenRefusal,
} from "../client/client.ts";
import { deletionOf } from "../deletion/deletion.ts";
import {
	assertedBy,
	type Checks,
	type Context,
	type CoreKind,
	continuationOf,
	isCoreKind,
	type Opened,
	oneOf,
	readPreimage,
	statementOf,
	statements,
	within,
} from "../evidence/evidence.ts";
import {
	abandonedFamily,
	acceptable,
	type Changes,
	type FlowEntry,
	type FlowState,
	own,
} from "../fold/fold.ts";
import { approverRefusal } from "../parent/parent.ts";

/** The fields a Core writer names, in its request and its record alike. */
export type Named = Pick<
	AppendRequest,
	| "kind"
	| "flow"
	| "op"
	| "stage"
	| "last"
	| "approval"
	| "keyChange"
	| "tokens"
	| "abandons"
	| "registryVersion"
	| "elements"
>;

/** A Core writer's record as the rules read it, before its append or after: against its flow's judged prefix. */
export interface Ask {
	readonly record: Named;
	/** The preimage as opened: the Core's own, or what the monitor decrypted. */
	readonly preimage: unknown;
	/** The state the flow's prefix folds to (M; the Core's Store). */
	readonly state: FlowState;
	/** The flow's judged entries before the record, from position 1. */
	readonly prior: readonly FlowEntry[];
	readonly checks: Checks;
	readonly context: Context;
	/**
	 * On a client's start: its client's record at the registry version it names, null where that
	 * version names no such client. Where none is given, the start is unchecked, so held.
	 */
	readonly client?: ClientAt | null | undefined;
}

/** Whether a record is allowed, and why not. */
export type Allowance =
	| { readonly allowed: true }
	| { readonly allowed: false; readonly reason: string };

type Read<K extends CoreKind> = Opened<K> & { readonly ask: Ask };
type Refusal = string | undefined;

const onSubject = (ask: Ask): Refusal =>
	ask.record.flow.of === "subject" ? undefined : "a person's op is on a subject flow";
/** A start's or a bundle's flow, by how it roots: a client's on its own flow, a person's on a subject's. */
const onRootsFlow = (read: Read<"start"> | Read<"bundle">): Refusal => {
	if (read.content.via !== "client") return onSubject(read.ask);
	return read.ask.record.flow.of === "client" ? undefined : "a client's op is on its own flow";
};
const oneStage = (ask: Ask): Refusal =>
	ask.record.stage === 1 && ask.record.last ? undefined : "the op is one stage";
const stageBefore = (ask: Ask) =>
	ask.prior.find(
		(e) => e.envelope.op === ask.record.op && e.envelope.stage === ask.record.stage - 1,
	);
const used = (state: FlowState, mark: string) => state.consumed.includes(mark);
const marks = {
	statement: (sid: string) => `statement:${sid}`,
	code: (approval: string) => `code:${approval}`,
};

/** The authorization T and the key an approval names, verified; or why not. */
function approvalOf(read: Read<"approval">) {
	const { ask, preimage } = read;
	const statement = oneOf(preimage, "statement");
	const asserted = oneOf(preimage, "assertion");
	if (statement === undefined || asserted === undefined)
		return { refusal: "an approval carries one statement and one assertion" };
	const t = statementOf(statement, statements.authorization, ask.checks, ask.context);
	if (!t) return { refusal: "the statement is not signed by the writer generation's ring" };
	return { t, statement, asserted };
}

function approvalRefusal(read: Read<"approval">): Refusal {
	const { ask, preimage } = read;
	const of = approvalOf(read);
	if ("refusal" in of) return of.refusal;
	const key = preimage.parent === undefined ? undefined : own(ask.state.keys, preimage.parent);
	if (!key) return "the assertion's key is not live on the flow";
	if (!assertedBy(of.asserted, key, of.statement, ask.checks, ask.context))
		return "the assertion is not the key's over the statement";
	if (used(ask.state, marks.statement(of.t.sid))) return "the statement is used";
	const bound = ask.record.approval;
	const { digest } = ask.checks;
	if (bound?.statement !== digest(of.statement) || bound.assertion !== digest(of.asserted))
		return "the envelope binds other evidence than the preimage's";
	return undefined;
}

/**
 * A first key's evidence, in one order by its path (proposal 3.13): the creation, the screen's
 * continuation, the possession, the new key's assertion; a sign-up's (F1) after its T.
 */
const firstForms = {
	firstKey: ["statement", "continuation", "statement", "assertion"],
	signUp: ["statement", "statement", "continuation", "statement", "assertion"],
} as const;

/** A first key's statements, each verified by the writer generation's ring, and its continuation read. */
function firstOf(read: Read<"keyChange">) {
	const { ask, preimage } = read;
	const forms = preimage.evidence.map((e) => e.form);
	const values = preimage.evidence.map((e) => e.value);
	const path = (Object.keys(firstForms) as (keyof typeof firstForms)[]).find(
		(k) => forms.length === firstForms[k].length && forms.every((f, at) => f === firstForms[k][at]),
	);
	if (!path)
		return {
			refusal:
				"a first key carries its creation, continuation, possession and assertion in order, a sign-up's after its T",
		};
	const at = path === "signUp" ? 1 : 0;
	const creation = values[at] ?? "";
	const possession = values[values.length - 2] ?? "";
	const proof = values[values.length - 1] ?? "";
	const sent = values[at + 1] ?? "";
	const signed = <T>(jws: string, schema: Parameters<typeof statementOf<T>>[1]) =>
		statementOf(jws, schema, ask.checks, ask.context);
	const c = signed(creation, statements.creation);
	const p = signed(possession, statements.possession);
	if (!c || !p)
		return {
			refusal: "the creation and possession are not both signed by the writer generation's ring",
		};
	const tJws = path === "signUp" ? (values[0] ?? "") : undefined;
	const tRead = tJws === undefined ? undefined : signed(tJws, statements.authorization);
	if (tJws !== undefined && !tRead)
		return { refusal: "the T is not signed by the writer generation's ring" };
	const continued = continuationOf(sent);
	if (!continued) return { refusal: "the continuation does not read" };
	const t = tJws !== undefined && tRead ? { jws: tJws, payload: tRead } : undefined;
	return { creation, c, possession, p, proof, continued, t };
}

type FirstOf = Exclude<ReturnType<typeof firstOf>, { refusal: string }>;

/** Why the new key is not the one the possession names by its thumbprint, of an algorithm the creation offered. */
function newKeyRefusal(
	checks: Checks,
	creation: { readonly options: { readonly algorithms: readonly number[] } },
	p: { readonly key_jkt: string },
	publicKey: string,
): Refusal {
	const key = checks.keyThumbprint(publicKey);
	if (!key) return "the new key is not a key the protocol takes";
	if (!creation.options.algorithms.includes(key.alg))
		return "the new key's algorithm is not one the creation offered";
	return p.key_jkt === key.jkt ? undefined : "the signed bytes are not the record's";
}

/** Why the screen's continuation is not its E_sig's over the creation, sending the record's key. */
function continuedRefusal(
	checks: Checks,
	of: { readonly creation: string; readonly c: { readonly e_sig: { x: string; y: string } } },
	continued: { readonly seq: number; readonly body: string; readonly signature: string },
	content: { readonly credential: string; readonly publicKey: string },
): Refusal {
	const { seq, body, signature } = continued;
	const input = continuations.of("register", checks.digest(of.creation), seq, checks.digest(body));
	if (!checks.verifyEsig(of.c.e_sig, input, signature))
		return "the continuation is not the screen's over the creation";
	const sent = checks.attestedKey(body);
	if (sent?.credential !== content.credential || sent.publicKey !== content.publicKey)
		return "the continuation sends another key than the record's";
	return undefined;
}

/**
 * Why a first key's path is not the one its signed creation names (`basis`): the first-key path's
 * (none or `first-key`) on a flow with no live key; a sign-up's (F1) as the flow's first record, for
 * its T, with the T's screen keys. A passkey-add's creation is no first key's.
 */
function pathRefusal(ask: Ask, of: FirstOf): Refusal {
	const made = of.c.creation;
	if (made.basis === undefined || made.basis === "first-key") {
		if (of.t) return "a first key's T is a sign-up's alone";
		if (Object.keys(ask.state.keys).length > 0)
			return "the flow has a live key: first trust takes a flow with none";
		return undefined;
	}
	if (made.basis !== "sign-up") return "the creation is not for a first key";
	if (!of.t) return "a sign-up's key comes after its T";
	if (ask.prior.length > 0) return "the flow has a record: a sign-up's key is its first";
	if (made.evidence !== ask.checks.digest(of.t.jws)) return "the creation is not for its T";
	if (!sameScreen(of.t.payload, of.c)) return "the creation names another screen's keys than its T";
	return undefined;
}

function firstKeyRefusal(read: Read<"keyChange">): Refusal {
	const { ask, preimage, content } = read;
	if (content.variant === "delete") return "a deletion registers no key";
	if (preimage.parent !== undefined || preimage.root !== undefined)
		return "a first key names no parent or root: it is its own root";
	const of = firstOf(read);
	if ("refusal" in of) return of.refusal;
	const path = pathRefusal(ask, of);
	if (path) return path;
	const made = of.c.creation;
	if (made.kg !== ask.state.keyGeneration)
		return "the creation is signed for another key generation than the flow's";
	if (made.subject !== ask.record.flow.id) return "the creation is another subject's";
	const continued = continuedRefusal(ask.checks, of, of.continued, content);
	if (continued) return continued;
	return possessionRefusal(ask, of, [of.t?.payload, of.c, of.p], content);
}

/** A passkey-add's evidence, in its one order: its root, the creation, the continuation, the possession. */
const addForms = ["statement", "assertion", "statement", "continuation", "statement", "assertion"];

/** A passkey-add's statements, each verified by the writer generation's ring, and its continuation read. */
function addOf(read: Read<"keyChange">) {
	const { ask, preimage } = read;
	const forms = preimage.evidence.map((e) => e.form);
	if (forms.length !== addForms.length || forms.some((f, at) => f !== addForms[at]))
		return {
			refusal: "a passkey-add carries its root, creation, continuation and possession in order",
		};
	const [statement = "", asserted = "", creation = "", sent = "", possession = "", proof = ""] =
		preimage.evidence.map((e) => e.value);
	const signed = <T>(jws: string, schema: Parameters<typeof statementOf<T>>[1]) =>
		statementOf(jws, schema, ask.checks, ask.context);
	const t = signed(statement, statements.passkeyAdd);
	const c = signed(creation, statements.creation);
	const p = signed(possession, statements.possession);
	if (!t || !c || !p)
		return { refusal: "a statement is not signed by the writer generation's ring" };
	const continued = continuationOf(sent);
	if (!continued) return { refusal: "the continuation does not read" };
	return { statement, asserted, t, creation, c, continued, possession, p, proof };
}

const sameScreen = (a: { e_enc: string; e_sig: object }, b: typeof a) =>
	a.e_enc === b.e_enc && canonicalText(a.e_sig) === canonicalText(b.e_sig);

/**
 * A key a live key's approval adds (proposal 3.13's order): the approval over its passkey-add, the
 * creation for it with the same screen's keys, the screen's E_sig over the creation and the new key,
 * the possession of that key, one key from one passkey-add.
 */
function addRefusal(read: Read<"keyChange">): Refusal {
	const { ask, preimage, content } = read;
	if (content.variant === "delete") return "a deletion registers no key";
	const { checks } = ask;
	const of = addOf(read);
	if ("refusal" in of) return of.refusal;
	const parent = preimage.parent === undefined ? undefined : own(ask.state.keys, preimage.parent);
	if (!parent) return "the approving key is not live on the flow";
	if (Object.values(ask.state.keys).some((k) => k.credential === content.credential))
		return "the flow holds a live key of that credential";
	if (!assertedBy(of.asserted, parent, of.statement, checks, ask.context))
		return "the assertion is not the approving key's over the passkey-add";
	if (used(ask.state, marks.statement(of.t.sid))) return "the statement is used";
	const { creation: made } = of.c;
	if (made.basis !== "passkey-add" || made.evidence !== checks.digest(of.statement))
		return "the creation is not for its passkey-add";
	const parentRefusal = approverRefusal(checks, parent.publicKey, made.approver_key);
	if (parentRefusal) return parentRefusal;
	if (made.subject !== ask.record.flow.id) return "the creation is another subject's";
	if (made.kg !== ask.state.keyGeneration)
		return "the creation is signed for another key generation than the flow's";
	if (!sameScreen(of.t, of.c))
		return "the creation names another screen's keys than its passkey-add";
	const continued = continuedRefusal(checks, of, of.continued, content);
	if (continued) return continued;
	return possessionRefusal(ask, of, [of.t, of.c, of.p], content);
}

/** A key's deletion (V24): `deletion`'s reading, its passkey-manage unused, the envelope naming its digests. */
function deleteRefusal(read: Read<"keyChange">): Refusal {
	const of = deletionAt(read);
	if ("refusal" in of) return of.refusal;
	if (used(read.ask.state, marks.statement(of.sid))) return "the statement is used";
	return keyChangeBound(read.ask, of.statement, of.body);
}

/** A key change's record read as a deletion, on the state just before it. */
const deletionAt = ({ ask, preimage, content }: Read<"keyChange">) =>
	deletionOf({
		state: ask.state,
		checks: ask.checks,
		context: ask.context,
		parent: preimage.parent,
		evidence: preimage.evidence,
		credential: content.credential,
	});

/**
 * Why a key change's possession does not bind the record (P 355): its statements one issuer's; the
 * possession naming the creation's digest, the credential, the new key by its thumbprint and the
 * reservation whose id is the record's op; the new key asserting it; the envelope's digests its own.
 */
function possessionRefusal(
	ask: Ask,
	of: {
		readonly creation: string;
		readonly c: { readonly creation: Parameters<typeof newKeyRefusal>[1] };
		readonly possession: string;
		readonly p: { readonly possession: PossessionPayload["possession"] };
		readonly proof: string;
	},
	statements: readonly ({ readonly iss: string } | undefined)[],
	content: { readonly credential: string; readonly publicKey: string },
): Refusal {
	const issuers = new Set(statements.flatMap((s) => (s ? [s.iss] : [])));
	if (issuers.size !== 1) return "the statements are not one issuer's";
	const p = of.p.possession;
	const named = newKeyRefusal(ask.checks, of.c.creation, p, content.publicKey);
	if (named) return named;
	if (p.creation_hash !== ask.checks.digest(of.creation) || p.credential_id !== content.credential)
		return "the signed bytes are not the record's";
	if (p.reservation_id !== ask.record.op)
		return "the possession is for another reservation than the op";
	if (!assertedBy(of.proof, content, of.possession, ask.checks, ask.context))
		return "the new key does not assert the possession";
	return keyChangeBound(ask, of.possession, of.proof);
}

/**
 * A key change's envelope digests, the preimage's own (proposal 3.13, V22): its statement's and its
 * evidence's, as a screen checks its receipt by them. Named otherwise, a taken Core could show the
 * screen its own digests over another key's evidence; naming none, its receipt binds nothing.
 */
function keyChangeBound(ask: Ask, statement: string, evidence: string): Refusal {
	const bound = ask.record.keyChange;
	const { digest } = ask.checks;
	if (!bound) return "the envelope names no key change's digests";
	if (bound.statement !== digest(statement) || bound.evidence !== digest(evidence))
		return "the envelope binds other evidence than the preimage's";
	return undefined;
}

/** A client's start (V23): its op id and elements its evidence's, unused on the flow, its evidence its client's. */
function clientStartRefusal(read: Read<"start">): Refusal {
	const { ask, preimage } = read;
	const { record } = ask;
	if (preimage.parent !== undefined || preimage.root !== undefined)
		return "a client's start names no parent or root: it roots in its flow's client";
	const start = startOf(preimage.evidence, ask.checks.digest);
	if ("refused" in start) return start.refused;
	if (record.op !== start.op) return "the op id is not its evidence's digest";
	const named = record.elements ?? [];
	if (named.length !== start.elements.length || start.elements.some((e) => !named.includes(e)))
		return "the elements named are not its evidence's";
	// The elements named, as the log indexes them, against every client's start before it.
	if (ask.prior.some((e) => e.client?.elements.some((x) => named.includes(x))))
		return "an evidence element is used on the flow";
	if (record.registryVersion === undefined) return "a client's start names its registry version";
	if (ask.client === null) return "its registry version names no such client";
	if (ask.client === undefined) return undefined;
	const evidence = evidenceRead(record.flow.id, ask.client, start.evidence, ask.checks);
	return "refused" in evidence ? evidence.refused : undefined;
}

/**
 * J2's second start: a code's start of this approval already on the flow, whatever its verdict
 * (every start accepted counts; a refresh's and a client's are not a code's). The judgment's row J2
 * and the Core's local check (`allowed`) both read it here. No approval named matches a code's start
 * that named none, as the judgment always read it (`allowed` refuses such a start first).
 */
export const codeStartedBefore = (prior: readonly FlowEntry[], approval: string | undefined) =>
	prior.some((e) => e.envelope.kind === "start" && e.via === "code" && e.parent === approval);

function startRefusal(read: Read<"start">): Refusal {
	const { ask, preimage, content } = read;
	if (ask.record.stage !== 1 || ask.record.last)
		return "a start is an op's first stage, not its last";
	if (content.via === "client") return clientStartRefusal(read);
	const parent = preimage.parent;
	if (parent === undefined) return "the start names no parent";
	if (content.via === "code") {
		const approval = own(ask.state.approvals, parent);
		if (!approval) return "the approval is not live on the flow";
		// V24 (A21): the code and the client its approval's record names, never another live approval's.
		if (content.code !== approval.code || content.client !== approval.client)
			return "the start names another code or client than its approval";
		if (used(ask.state, marks.code(parent))) return "the approval's code is exchanged";
		// J2's, for the Core's local check before its append; the judgment meets it first at J2.
		if (codeStartedBefore(ask.prior, parent)) return "an approval's code is exchanged once";
		return undefined;
	}
	const family = own(ask.state.families, parent);
	if (!family) return "the family is not live on the flow";
	if (!rootKeyLive(ask.state, family.chain)) return "the family's root key is not live";
	return content.rotation === family.rotation ? undefined : "the refresh is of another rotation";
}

/**
 * Whether the key a chain ends in, an approval's or a family's root key, is live on the state just
 * before the record (V24): a family is made, and refreshed, only while it is. The state is the prefix's
 * (`StateOf(f, p)`), whatever an honest Core read when it decided.
 */
const rootKeyLive = (state: FlowState, chain: readonly string[]) => {
	const key = chain.at(-1);
	return key !== undefined && own(state.keys, key) !== undefined;
};

function bundleRefusal(read: Read<"bundle">): Refusal {
	const { ask, preimage, content } = read;
	if (ask.record.stage < 2 || !ask.record.last)
		return "a bundle is an op's last stage, after its start";
	const start = stageBefore(ask);
	if (start?.envelope.kind !== "start") return "no start of the op before its bundle";
	if (preimage.parent !== start.envelope.id) return "the bundle names another start than its op's";
	if (content.via === "client") return clientBundleRefusal(read, content.token, start);
	const root = preimage.root;
	if (root === undefined) return "the bundle names no root";
	// A forged parent's descendant is forged (J7), the start's verdict read before its own root.
	if (start.judgment.verdict === "forged") return "the bundle's start is forged";
	// A start whose preimage was not read (J5, J6) leaves its root to J9 (KG-20); any read one is held to it.
	if (start.parent !== undefined && start.parent !== root)
		return "the bundle roots elsewhere than its start";
	if (content.via === "code") {
		const approval = own(ask.state.approvals, root);
		if (!approval) return "the approval is not live on the flow";
		if (used(ask.state, marks.code(root))) return "the approval's code is exchanged";
		if (start.envelope.acceptedAt > approval.acceptedAt + ask.context.limits.codeLifetime)
			return "the start came after the code's lifetime";
		const founds = (ask.record.tokens ?? []).some((token) => token.frame === "family");
		if (founds && !rootKeyLive(ask.state, approval.chain))
			return "the bundle founds a family on an approval whose key is not live";
	} else {
		const family = own(ask.state.families, root);
		if (!family) return "the family is not live on the flow";
		if (!rootKeyLive(ask.state, family.chain)) return "the family's root key is not live";
		if (content.rotation !== family.rotation) return "the refresh is of another rotation";
	}
	if (acceptable(start.judgment.verdict) && start.judgment.outcome === "didNotTake")
		return "a stage after one that did not take";
	return undefined;
}

/** A client's bundle (V23, V21): after its client's start, one access token of its client. */
function clientBundleRefusal(
	read: Read<"bundle">,
	texts: { readonly header: string; readonly claims: string },
	start: FlowEntry,
): Refusal {
	const { ask, preimage } = read;
	if (start.judgment.verdict === "forged") return "the bundle's start is forged";
	if (preimage.root !== undefined)
		return "a client's bundle names no root: it roots in its flow's client";
	if (start.via !== undefined && start.via !== "client")
		return "the bundle roots elsewhere than its start";
	const refusal = tokenRefusal({
		client: ask.record.flow.id,
		digests: ask.record.tokens,
		texts,
		start: {
			acceptedAt: start.envelope.acceptedAt,
			version: start.client?.version,
			key: start.client?.key,
		},
		checks: ask.checks,
	});
	if (refusal !== undefined) return refusal;
	if (acceptable(start.judgment.verdict) && start.judgment.outcome === "didNotTake")
		return "a stage after one that did not take";
	return undefined;
}

function noEffectRefusal(read: Read<"noEffect">): Refusal {
	const before = stageBefore(read.ask);
	if (!before) return "the record reports no stage of its op";
	if (acceptable(before.judgment.verdict) && before.judgment.outcome === "took")
		return "the record says a stage that took did not take";
	return undefined;
}

type Rule<K extends CoreKind> = (read: Read<K>) => Refusal;
const rules: { readonly [K in CoreKind]: Rule<K> } = {
	approval: (read) => onSubject(read.ask) ?? oneStage(read.ask) ?? approvalRefusal(read),
	keyChange: (read) =>
		onSubject(read.ask) ??
		oneStage(read.ask) ??
		(read.content.variant === "add"
			? addRefusal(read)
			: read.content.variant === "delete"
				? deleteRefusal(read)
				: firstKeyRefusal(read)),
	start: (read) => onRootsFlow(read) ?? startRefusal(read),
	bundle: (read) => onRootsFlow(read) ?? bundleRefusal(read),
	noEffect: noEffectRefusal,
	// Allowed with no record of the op, and after its family is gone (§6.3; Step023 Allowed).
	abandonment: () => undefined,
};

function readOf<K extends CoreKind>(kind: K, ask: Ask): Read<K> | undefined {
	const opened = readPreimage(kind, ask.preimage);
	return "error" in opened ? undefined : { ...opened, ask };
}

/** Why a record is not allowed (its first broken rule), none where it is. */
export function refusalOf(ask: Ask): Refusal {
	const kind = ask.record.kind;
	if (!isCoreKind(kind)) return "not a Core writer's kind";
	const read = readOf(kind, ask);
	if (!read) return "the preimage's content does not read as its kind's";
	return (rules[kind] as Rule<typeof kind>)(read);
}

/**
 * Why a client's start or bundle is unchecked, so held: a check its rules need the caller did not
 * give (the client's record, the evidence window, the self ceiling) or its start's key is not known.
 */
export function uncheckedOf(ask: Ask): string | undefined {
	const kind = ask.record.kind;
	if (kind !== "start" && kind !== "bundle") return undefined;
	if (readOf(kind, ask)?.content.via !== "client") return undefined;
	if (kind === "start") {
		if (ask.client === undefined) return "the client's record at its version is not given";
		if (ask.context.limits.evidenceWindow === undefined) return "no evidence window is given";
		return undefined;
	}
	if (!ask.checks.selfCeiling) return "no self ceiling is given";
	if (stageBefore(ask)?.client?.key === undefined) return "its start's key is not known";
	return undefined;
}

/** A client's start's entry fields: the elements and version it names, its evidence's key where read. */
export function clientOf(ask: Ask): FlowEntry["client"] {
	const { record } = ask;
	if (record.kind !== "start" || record.flow.of !== "client" || !record.elements) return undefined;
	const read = readOf("start", ask);
	const start = read && startOf(read.preimage.evidence, ask.checks.digest);
	const evidence =
		read?.content.via === "client" && ask.client && start && !("refused" in start)
			? evidenceRead(record.flow.id, ask.client, start.evidence, ask.checks)
			: undefined;
	return {
		elements: record.elements,
		...(record.registryVersion === undefined ? {} : { version: record.registryVersion }),
		...(evidence && !("refused" in evidence) ? { key: evidence.key } : {}),
	};
}

/**
 * Allowed(r, S): whether a Core writer's record keeps the chain rules on its flow's state and judged
 * prefix. The Core's local check calls it before the append, the monitor's judgment (J7) after.
 */
export function allowed(ask: Ask): Allowance {
	const reason = refusalOf(ask);
	return reason === undefined ? { allowed: true } : { allowed: false, reason };
}

/**
 * TimeOK (§6.2): whether a Core writer's record keeps its time rules, judged by its acceptance time.
 * Each bound holds at its edge, as §6.2's `statement の時刻 ≦ a ≦ 期限` and BundleEscape023's
 * `LateStart` (a start is late past a_A + L) do: the code's lifetime, the family's, the issue window.
 */
export function timely(ask: Ask, acceptedAt: number): boolean {
	const kind = ask.record.kind;
	if (!isCoreKind(kind)) return true;
	const { limits } = ask.context;
	const parent = (read: Read<"start">) => read.preimage.parent ?? "";
	switch (kind) {
		case "approval": {
			const read = readOf("approval", ask);
			const of = read && approvalOf(read);
			return of !== undefined && !("refusal" in of) && within(of.t, acceptedAt);
		}
		case "keyChange": {
			const read = readOf("keyChange", ask);
			if (read?.content.variant === "add") {
				const of = addOf(read);
				return !("refusal" in of) && [of.t, of.c, of.p].every((s) => within(s, acceptedAt));
			}
			if (read?.content.variant === "delete") {
				const of = deletionAt(read);
				return !("refusal" in of) && within(of.times, acceptedAt);
			}
			// A sign-up's T is held to its times by the approval that uses it, after the key (F1).
			const of = read && firstOf(read);
			return (
				of !== undefined &&
				!("refusal" in of) &&
				within(of.c, acceptedAt) &&
				within(of.p, acceptedAt)
			);
		}
		case "start": {
			const read = readOf("start", ask);
			if (!read) return false;
			if (read.content.via === "client") {
				const window = limits.evidenceWindow;
				const start = startOf(read.preimage.evidence, ask.checks.digest);
				if (window === undefined || !ask.client || "refused" in start) return false;
				const evidence = evidenceRead(ask.record.flow.id, ask.client, start.evidence, ask.checks);
				return !("refused" in evidence) && evidenceTimely(evidence, acceptedAt, window);
			}
			if (read.content.via === "code") {
				const approval = own(ask.state.approvals, parent(read));
				return approval !== undefined && acceptedAt <= approval.acceptedAt + limits.codeLifetime;
			}
			const family = own(ask.state.families, parent(read));
			return family !== undefined && acceptedAt <= family.acceptedAt + limits.refreshLifetime;
		}
		case "bundle": {
			const start = stageBefore(ask);
			return start !== undefined && acceptedAt <= start.envelope.acceptedAt + limits.issueWindow;
		}
		default:
			return true;
	}
}

/** What a record's chain rests on: a first-trust key itself, or the root first-trust key's registration. */
export type Root = { readonly first: true } | { readonly root: string };

/** The root a record's chain rests on; none for a record resting on no key, or whose chain is not live. */
export function rootOf(ask: Ask): Root | undefined {
	const kind = ask.record.kind;
	const { state } = ask;
	const rootOfChain = (
		item: { chain: readonly string[] } | undefined,
		self?: string,
	): Root | undefined => {
		const root = item ? (item.chain[0] ?? self) : undefined;
		return root === undefined ? undefined : { root };
	};
	if (kind === "keyChange") {
		const read = readOf("keyChange", ask);
		// An added key's and a deletion's chains rest on their approving key's root.
		if (read === undefined || read.content.variant === "first") return { first: true } as const;
		const parent = read.preimage.parent;
		return parent === undefined ? undefined : rootOfChain(own(state.keys, parent), parent);
	}
	if (kind === "approval") {
		const parent = readOf("approval", ask)?.preimage.parent;
		return parent === undefined ? undefined : rootOfChain(own(state.keys, parent), parent);
	}
	if (kind === "start" || kind === "bundle") {
		const read = readOf(kind, ask);
		const at = kind === "start" ? read?.preimage.parent : read?.preimage.root;
		// A client's chain rests on its client in the registry, no first-trust key (J12 not asked).
		if (!read || at === undefined || read.content.via === "client") return undefined;
		return rootOfChain(
			read.content.via === "code" ? own(state.approvals, at) : own(state.families, at),
		);
	}
	return undefined;
}

/**
 * A bundle's changes, Eff of its record, the Core's intent and `effectOf` alike: a code's consumes its
 * code, and makes the family of its approval only where it carries a `family` frame (V24); a refresh's
 * rotates its family; a client's, or one of no root, none. `frames` are its tokens' frames, in order.
 */
export function bundleEffect(b: {
	readonly via: "code" | "refresh" | "client" | undefined;
	readonly root: string | undefined;
	readonly frames: readonly string[];
}): Changes {
	if (b.root === undefined || b.via === undefined || b.via === "client") return {};
	if (b.via === "refresh") return { rotate: b.root };
	const family = b.frames.includes("family") ? { family: { approval: b.root } } : {};
	return { ...family, consume: [marks.code(b.root)] };
}

/** Eff(r): a Core writer's record's changes, from its preimage; the Core's intent holds the same. */
export function effectOf(ask: Ask): Changes {
	const kind = ask.record.kind;
	if (!isCoreKind(kind)) return {};
	switch (kind) {
		case "approval": {
			const read = readOf("approval", ask);
			const of = read && approvalOf(read);
			const key = read?.preimage.parent;
			const code = ask.record.approval?.code;
			if (!of || "refusal" in of || key === undefined || code === undefined) return {};
			return {
				approval: { key, code, client: of.t.approval.client_id },
				consume: [marks.statement(of.t.sid)],
			};
		}
		case "keyChange": {
			const read = readOf("keyChange", ask);
			if (!read) return {};
			if (read.content.variant === "delete") {
				const of = deletionAt(read);
				return "refusal" in of ? {} : { removeKey: of.deleted, consume: [marks.statement(of.sid)] };
			}
			const key = { credential: read.content.credential, publicKey: read.content.publicKey };
			if (read.content.variant !== "add") return { key };
			const by = read.preimage.parent;
			const of = addOf(read);
			if (by === undefined || "refusal" in of) return {};
			return { key: { ...key, by }, consume: [marks.statement(of.t.sid)] };
		}
		case "bundle": {
			const read = readOf("bundle", ask);
			if (!read) return {};
			const frames = (ask.record.tokens ?? []).map((token) => token.frame);
			return bundleEffect({ via: read.content.via, root: read.preimage.root, frames });
		}
		case "abandonment": {
			const op = ask.record.abandons?.op;
			const bundle = ask.prior.find((e) => e.envelope.kind === "bundle" && e.envelope.op === op);
			const family = bundle && abandonedFamily(bundle);
			return family === undefined ? {} : { abandon: family };
		}
		default:
			return {};
	}
}
