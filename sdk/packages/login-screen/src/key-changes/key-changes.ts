import { credentialsOf } from "@mod/flow-state-wire";
import { hpke, payloads } from "@mod/sdk-core-wire";
import { type Receipt, type SignerSet, schemas } from "@mod/transparency-wire";
import { digest, utf8 } from "../bytes.ts";
import { openCompletion } from "../completion.ts";
import { creationOfPossession, type ReadPossession } from "../first-key/first-key.ts";
import type { Sealed } from "../hpke.ts";
import { type Jwk, keyIdentity } from "../jws.ts";
import type { ScreenKeys } from "../keys.ts";
import { type Continued, wasSent } from "../management/management.ts";
import { readLogReceipt } from "../receipt.ts";
import { readSet, readSetSigned, setIdentities } from "./signed-set.ts";

type KeyChange = ReturnType<typeof payloads.completions.keyChange.parse>;

/** The key change the screen waits for: a key added (its possession and the new key's assertion's bytes), or a delete it sent. */
export type KeyChangeSource =
	| { readonly add: ReadPossession; readonly assertion: Uint8Array }
	| { readonly delete: Continued };

/**
 * How far a key change is checked, named by the caller (never a key list left out): `L0` (a bundle
 * that fixes no log keys) reads the completion alone; `log` also holds it to the log (§C.5's four),
 * every input required. A status or a stateOf fetched again is given here, in place of the
 * completion's.
 */
export type KeyChangeChecks =
	| { readonly level: "L0" }
	| {
			readonly level: "log";
			readonly log: readonly Jwk[];
			readonly statusSigners: unknown;
			readonly stateOfSigners: unknown;
			/** The oldest a receipt may be, the bundle's, in ms. */
			readonly maxAge: number;
			/** The screen's clock and how far the log's may stray from it, in ms. */
			readonly now: number;
			readonly skew: number;
			readonly status?: string;
			readonly stateOf?: string;
	  };

type PasskeyManageList = ReturnType<typeof payloads.completions.passkeyManage.parse>;

/** A delete the Core did not take: the person's keys as they are, and why (`last`, `used`, `unknown`). */
export interface KeptDelete {
	readonly keys: PasskeyManageList["keys"];
	readonly refused: "last" | "used" | "unknown";
}

/**
 * Why a key change is not taken, none of which a fetch changes: what was waited for, the inputs, the
 * completion (opening, signature, shape, issuer, purpose, the change itself; for a delete not taken, the list's statement and the delete it names), the receipt (missing
 * or not the log's, its kind, digests, flow, age), the status (unread, the record denied), the
 * stateOf (unread, another flow, the record's result, a state that does not read, the key there or not).
 */
export type KeyChangeError =
	| "source"
	| "checks"
	| "open"
	| "signature"
	| "typ"
	| "payload"
	| "issuer"
	| "purpose"
	| "change"
	| "statement"
	| "continued"
	| "receipt"
	| "kind"
	| "digest"
	| "flow"
	| "tooOld"
	| "status"
	| "denied"
	| "stateOf"
	| "result"
	| "state"
	| "key";

/**
 * What a fetch may change, with the receipt read (its flow, position, shard and n name what to
 * fetch): no status, the attached one not read, or one older than this page already read for the
 * same change (`status`); the same of the stateOf (`stateOf`); the record past the status's
 * watermark (`notYetChecked`); a stateOf before the record (`stateBehind`). The caller fetches the
 * one named from the log's source and reads again with it in the checks, success never shown before.
 */
export type KeyChangeRetry = "status" | "stateOf" | "notYetChecked" | "stateBehind";

/** Refusals the log's own objects gave: they stay with the change, whatever is given later. */
const final: readonly KeyChangeError[] = ["denied", "result", "state", "key"];

/** What this page has read for each change (its purpose, statement, op and credential): a final refusal, the newest status version and stateOf position. */
const seen = new Map<
	string,
	{ refused?: KeyChangeError; statusVersion: number; stateOfPosition: number }
>();
interface Waited {
	readonly purpose: KeyChange["purpose"];
	/** The statement's hash: the completion's additional data's `h` and the receipt's `keyChange.statement`. */
	readonly h: string;
	readonly change: KeyChange["change"];
	/** The receipt's `keyChange.evidence`: the new key's assertion's hash, or the delete's body's. */
	readonly evidence: string;
	/** A delete's sequence, read when it was waited for, so the list a delete not taken names is held to it. */
	readonly seq?: number;
	/** The subject's flow, where the statement names it (an add); a delete's is the receipt's. */
	readonly subject?: string;
}

async function waited(source: KeyChangeSource): Promise<Waited | undefined> {
	if ("add" in source) {
		const creation = creationOfPossession(source.add);
		const basis = creation?.statement.creation.basis ?? "first-key";
		if (!creation) return undefined;
		const { credential_id, key_jkt } = source.add.statement.possession;
		return {
			purpose: basis,
			h: await digest(source.add.compact),
			change: { op: "add", credential_id, key_jkt },
			evidence: await digest(source.assertion),
			subject: creation.statement.creation.subject,
		};
	}
	const sent = source.delete;
	if (!wasSent(sent) || sent.stage !== "delete") return undefined;
	return {
		purpose: "passkey-manage",
		h: await digest(sent.manage.compact),
		change: { op: "delete", credential_id: sent.body.credential_id },
		evidence: sent.bodyHash,
		seq: sent.seq,
	};
}

/** A delete not taken: the list, for the statement answered, naming exactly the delete sent, and why. */
function keptOf(
	list: PasskeyManageList,
	want: Waited,
	issuer: string,
): { readonly kept: KeptDelete } | { readonly error: KeyChangeError } {
	if (list.iss !== issuer) return { error: "issuer" };
	if (list.t_hash !== want.h) return { error: "statement" };
	// Held to what was read when the delete was waited for, never to the source as it is now.
	const named = list.continued;
	if (named?.stage !== "delete" || named.seq !== want.seq || named.body_hash !== want.evidence)
		return { error: "continued" };
	return Object.freeze({ kept: Object.freeze({ keys: list.keys, refused: named.refused }) });
}

const sameChange = (a: KeyChange["change"], b: KeyChange["change"]) =>
	a.op === b.op &&
	a.credential_id === b.credential_id &&
	(a.op === "add" ? b.op === "add" && a.key_jkt === b.key_jkt : true);

/** The log inputs as read: copies of their own, taken before anything is awaited. */
interface LogInputs {
	readonly log: readonly Jwk[];
	readonly statusSigners: SignerSet;
	readonly stateOfSigners: SignerSet;
	readonly maxAge: number;
	readonly now: number;
	readonly skew: number;
	readonly status?: string;
	readonly stateOf?: string;
}

/**
 * The log inputs, read: a list of log keys (copied), both sets read as the wire's (copies), finite
 * times, and no key of the log's or the sets' one of the Core ring's (a Core holding both would sign
 * its own proof); none otherwise.
 */
function logInputs(
	given: Extract<KeyChangeChecks, { level: "log" }>,
	ring: readonly Jwk[],
): LogInputs | undefined {
	const { now, skew, maxAge, status, stateOf } = given;
	if (![now, skew, maxAge].every(Number.isFinite) || skew < 0 || maxAge < 0) return undefined;
	if (!Array.isArray(given.log) || given.log.length === 0) return undefined;
	let log: Jwk[];
	try {
		log = structuredClone(given.log) as Jwk[];
	} catch {
		return undefined;
	}
	const statusSigners = readSet(given.statusSigners);
	const stateOfSigners = readSet(given.stateOfSigners);
	if (!statusSigners || !stateOfSigners) return undefined;
	if (typeof status !== "string" && status !== undefined) return undefined;
	if (typeof stateOf !== "string" && stateOf !== undefined) return undefined;
	const core = new Set(ring.map(keyIdentity).filter((id) => id !== undefined));
	const theirs = [
		...log.map((key) => keyIdentity(key) ?? ""),
		...setIdentities(statusSigners),
		...setIdentities(stateOfSigners),
	];
	if (!theirs.every((id) => id !== "" && !core.has(id))) return undefined;
	return {
		log,
		statusSigners,
		stateOfSigners,
		maxAge,
		now,
		skew,
		...(status === undefined ? {} : { status }),
		...(stateOf === undefined ? {} : { stateOf }),
	};
}

/**
 * A key change's completion (`keyFinish`, or `continue`'s delete; sealed), taken only for what the
 * screen waited for: opened under `completionAad` of the path's purpose and the statement's hash,
 * the ring's, of its schema, the issuer's, its purpose the path's and its change exactly the one
 * waited for (an add: the possession's credential and key; a delete: the body sent). At `log`, §C.5:
 * (1) its receipt the log's, a key change's, binding the statement's hash and the evidence (the new
 * key's assertion, or the delete's body), of the subject's flow (an add's; a delete's statement
 * names none, so its flow is the receipt's, which the stateOf must share), accepted no later than
 * now; (2) no older than `maxAge`; (3) a status its set signed covering the record, not denying it;
 * (4) a stateOf its set signed, of that flow, at or past the record, the record's result verified
 * or unsupported and took, its state (flow-state-wire's read) holding the key added, or not the one
 * deleted. The checks and the ring are copied before anything is awaited. A refusal the log's
 * objects gave stays with the change, and a status or stateOf older than one read before for it is
 * fetched again, so no older object, no source made again, nor a read of the same change running
 * beside this one, undoes what was read: what was read is merged into what the page holds, which is
 * read again before success.
 */
async function read(
	source: KeyChangeSource,
	sealed: Sealed,
	options: {
		readonly ring: readonly Jwk[];
		readonly keys: ScreenKeys;
		readonly issuer: string;
		readonly checks: KeyChangeChecks;
	},
): Promise<
	| { readonly change: KeyChange["change"]; readonly receipt?: Receipt }
	| { readonly kept: KeptDelete }
	| { readonly error: KeyChangeError }
	| { readonly retry: KeyChangeRetry; readonly receipt: Receipt }
> {
	const given = options.checks;
	if (given?.level !== "L0" && given?.level !== "log") return { error: "checks" };
	let ring: Jwk[];
	try {
		ring = structuredClone([...options.ring]) as Jwk[];
	} catch {
		return { error: "checks" };
	}
	const checks = given.level === "log" ? logInputs(given, ring) : undefined;
	if (given.level === "log" && !checks) return { error: "checks" };
	const want = await waited(source);
	if (!want) return { error: "source" };
	const opened = await openCompletion(sealed, {
		keys: options.keys,
		ring,
		aad: utf8(hpke.completionAad(want.purpose, want.h)),
		// A delete's is padded to a bucket, so its length tells no key deleted (sdk-core-wire).
		padded: want.purpose === "passkey-manage",
	});
	if ("error" in opened) return opened;
	const parsed = payloads.completions.keyChange.safeParse(opened.payload);
	if (!parsed.success) {
		// A delete the Core did not take is answered with the padded list, naming it and why.
		const list =
			"delete" in source ? payloads.completions.passkeyManage.safeParse(opened.payload) : undefined;
		return list?.success ? keptOf(list.data, want, options.issuer) : { error: "payload" };
	}
	const done = parsed.data;
	if (done.iss !== options.issuer) return { error: "issuer" };
	if (done.purpose !== want.purpose) return { error: "purpose" };
	if (!sameChange(done.change, want.change)) return { error: "change" };
	if (!checks) return { change: done.change };

	const name = `${want.purpose}|${want.h}|${want.change.op}|${want.change.credential_id}`;
	const held = () => seen.get(name) ?? { statusVersion: 0, stateOfPosition: 0 };
	/** Merges what was read into what the page holds: a refusal kept, the newest version and position. */
	const mark = (read: {
		refused?: KeyChangeError;
		statusVersion?: number;
		stateOfPosition?: number;
	}) => {
		const now = held();
		const refused = now.refused ?? read.refused;
		seen.set(name, {
			...(refused === undefined ? {} : { refused }),
			statusVersion: Math.max(now.statusVersion, read.statusVersion ?? 0),
			stateOfPosition: Math.max(now.stateOfPosition, read.stateOfPosition ?? 0),
		});
	};
	const refuse = (error: KeyChangeError) => {
		if (final.includes(error)) mark({ refused: error });
		return { error };
	};
	const kept = held().refused;
	if (kept) return { error: kept };

	// (1) The receipt.
	const receipt = done.receipt && (await readLogReceipt(done.receipt, checks.log));
	if (!receipt) return { error: "receipt" };
	if (receipt.acceptedAt > checks.now + checks.skew) return { error: "receipt" };
	if (receipt.kind !== "keyChange" || !receipt.keyChange) return { error: "kind" };
	if (receipt.keyChange.statement !== want.h || receipt.keyChange.evidence !== want.evidence)
		return { error: "digest" };
	if (receipt.flow.of !== "subject") return { error: "flow" };
	if (want.subject !== undefined && receipt.flow.id !== want.subject) return { error: "flow" };
	// (2) Its age.
	if (checks.now - checks.skew > receipt.acceptedAt + checks.maxAge) return { error: "tooOld" };
	// (3) The status: one fetched and not read is refused, one attached and not read is fetched again.
	const statusText = checks.status ?? done.status;
	const statusRead =
		statusText === undefined
			? undefined
			: schemas.status.safeParse(await readSetSigned(statusText, checks.statusSigners, "status"));
	if (!statusRead?.success)
		return checks.status === undefined ? { retry: "status", receipt } : { error: "status" };
	const status = statusRead.data;
	if (status.version < held().statusVersion) return { retry: "status", receipt };
	mark({ statusVersion: status.version });
	const shard = Object.hasOwn(status.shards, receipt.shard)
		? status.shards[receipt.shard]
		: undefined;
	if (!shard || receipt.n > shard.watermark) return { retry: "notYetChecked", receipt };
	if (status.deny.includes(receipt.id)) return refuse("denied");
	// (4) The stateOf, as the status.
	const stateOfText = checks.stateOf ?? done.stateOf;
	const stateOfRead =
		stateOfText === undefined
			? undefined
			: schemas.stateOf.safeParse(
					await readSetSigned(stateOfText, checks.stateOfSigners, "stateOf"),
				);
	if (!stateOfRead?.success)
		return checks.stateOf === undefined ? { retry: "stateOf", receipt } : { error: "stateOf" };
	const at = stateOfRead.data;
	if (at.flow.of !== receipt.flow.of || at.flow.id !== receipt.flow.id) return { error: "flow" };
	if (at.position < held().stateOfPosition) return { retry: "stateOf", receipt };
	if (at.position < receipt.position) return { retry: "stateBehind", receipt };
	mark({ stateOfPosition: at.position });
	const result = at.results[receipt.position - 1];
	const verdicts: readonly string[] = ["verified", "unsupported"];
	if (result?.id !== receipt.id || !verdicts.includes(result.verdict) || result.outcome !== "took")
		return refuse("result");
	const ids = credentialsOf(at.state);
	if (ids === undefined) return refuse("state");
	if (ids.includes(want.change.credential_id) !== (want.change.op === "add")) return refuse("key");
	// A read of the same change beside this one may have been refused, or read newer, meanwhile.
	const last = held();
	if (last.refused) return { error: last.refused };
	if (last.statusVersion > status.version) return { retry: "status", receipt };
	if (last.stateOfPosition > at.position) return { retry: "stateOf", receipt };
	return { change: done.change, receipt };
}

/** A key change's completion on the screen, at the level the caller names. */
export const keyChanges = Object.freeze({ read });
