import type { AppendRequest } from "@mod/transparency-wire";
import {
	type ClientAt,
	evidenceRead,
	evidenceTimely,
	startOf,
	tokenRefusal,
} from "../client/client.ts";
import {
	assertedBy,
	type Checks,
	type Context,
	type CoreKind,
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

/** The fields a Core writer names, in its request and its record alike. */
export type Named = Pick<
	AppendRequest,
	| "kind"
	| "flow"
	| "op"
	| "stage"
	| "last"
	| "approval"
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

/** The first-key path's creation and possession, each verified by the writer generation's ring. */
function ceremonyOf(read: Read<"keyChange">) {
	const { ask, preimage } = read;
	const signed = preimage.evidence.filter((e) => e.form === "statement").map((e) => e.value);
	const as = <T>(schema: Parameters<typeof statementOf<T>>[1]) =>
		signed
			.map((jws) => ({ jws, payload: statementOf(jws, schema, ask.checks, ask.context) }))
			.filter((s): s is { jws: string; payload: T } => s.payload !== undefined);
	const [creation, ...more] = as(statements.creation);
	const [possession, ...also] = as(statements.possession);
	if (!creation || !possession || more.length > 0 || also.length > 0) return undefined;
	return { creation, possession };
}

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

function firstKeyRefusal(read: Read<"keyChange">): Refusal {
	const { ask, preimage, content } = read;
	if (Object.keys(ask.state.keys).length > 0)
		return "the flow has a live key: first trust takes a flow with none";
	const ceremony = ceremonyOf(read);
	if (!ceremony)
		return "the creation and possession are not both signed by the writer generation's ring";
	const { creation, possession } = ceremony;
	if (creation.payload.creation.kg !== ask.state.keyGeneration)
		return "the creation is signed for another key generation than the flow's";
	if (creation.payload.creation.subject !== ask.record.flow.id)
		return "the creation is another subject's";
	const p = possession.payload.possession;
	const named = newKeyRefusal(ask.checks, creation.payload.creation, p, content.publicKey);
	if (named) return named;
	if (p.creation_hash !== ask.checks.digest(creation.jws) || p.credential_id !== content.credential)
		return "the signed bytes are not the record's";
	const asserted = oneOf(preimage, "assertion");
	if (
		asserted === undefined ||
		!assertedBy(asserted, content, possession.jws, ask.checks, ask.context)
	)
		return "the new key does not assert the possession";
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
		// J2 counts the code exchanges' starts alone, whatever their verdict; a refresh's is not one.
		const before = ask.prior.some(
			(e) => e.envelope.kind === "start" && e.via === "code" && e.parent === parent,
		);
		if (before) return "an approval's code is exchanged once";
		return undefined;
	}
	const family = own(ask.state.families, parent);
	if (!family) return "the family is not live on the flow";
	return content.rotation === family.rotation ? undefined : "the refresh is of another rotation";
}

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
	} else {
		const family = own(ask.state.families, root);
		if (!family) return "the family is not live on the flow";
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
	keyChange: (read) => onSubject(read.ask) ?? oneStage(read.ask) ?? firstKeyRefusal(read),
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
			const ceremony = read && ceremonyOf(read);
			return (
				ceremony !== undefined &&
				within(ceremony.creation.payload, acceptedAt) &&
				within(ceremony.possession.payload, acceptedAt)
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
	if (kind === "keyChange") return { first: true } as const;
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
			return read
				? { key: { credential: read.content.credential, publicKey: read.content.publicKey } }
				: {};
		}
		case "bundle": {
			const read = readOf("bundle", ask);
			const root = read?.preimage.root;
			if (!read || root === undefined || read.content.via === "client") return {};
			return read.content.via === "code"
				? { family: { approval: root }, consume: [marks.code(root)] }
				: { rotate: root };
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
