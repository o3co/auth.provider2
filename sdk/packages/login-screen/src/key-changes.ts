import { credentialsOf } from "@mod/flow-state-wire";
import { hpke, payloads } from "@mod/sdk-core-wire";
import { type Receipt, schemas } from "@mod/transparency-wire";
import { digest, utf8 } from "./bytes.ts";
import { openCompletion } from "./completion.ts";
import { creationOfPossession, type ReadPossession } from "./first-key.ts";
import type { Sealed } from "./hpke.ts";
import { type Jwk, keyIdentity } from "./jws.ts";
import type { ScreenKeys } from "./keys.ts";
import { type Continued, wasSent } from "./management.ts";
import { readLogReceipt } from "./receipt.ts";
import { readSetSigned, setIdentities } from "./signed-set.ts";

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

/**
 * Why a key change is not taken, none of which a fetch changes: what was waited for, the inputs, the
 * completion (opening, signature, shape, issuer, purpose, the change itself), the receipt (missing
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
 * fetch): no status, or the attached one not read (`status`); no stateOf, or the attached one not
 * read (`stateOf`); the record past the status's watermark (`notYetChecked`); a stateOf before the
 * record (`stateBehind`); a status or stateOf older than one this page already read for the same
 * change (`stale`). The caller fetches the one named from the log's source and reads again with it
 * in the checks, success never shown before.
 */
export type KeyChangeRetry = "status" | "stateOf" | "notYetChecked" | "stateBehind" | "stale";

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
	/** The subject's flow, where the statement names it (an add); a delete's is the receipt's. */
	readonly subject?: string;
}

async function waited(source: KeyChangeSource): Promise<Waited | undefined> {
	if ("add" in source) {
		const creation = creationOfPossession(source.add);
		const basis = creation?.statement.creation.basis ?? "first-key";
		if (!creation || basis === "sign-up") return undefined;
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
	};
}

const sameChange = (a: KeyChange["change"], b: KeyChange["change"]) =>
	a.op === b.op &&
	a.credential_id === b.credential_id &&
	(a.op === "add" ? b.op === "add" && a.key_jkt === b.key_jkt : true);

/** The log inputs, held: a key list, both sets read as the wire's, finite times, and no key of the log's or the sets' one of the Core ring's (a Core holding both would sign its own proof). */
function inputsHold(checks: Extract<KeyChangeChecks, { level: "log" }>, ring: readonly Jwk[]) {
	const times = [checks.now, checks.skew, checks.maxAge];
	if (!times.every(Number.isFinite) || checks.skew < 0 || checks.maxAge < 0) return false;
	const status = setIdentities(checks.statusSigners);
	const stateOf = setIdentities(checks.stateOfSigners);
	if (checks.log.length === 0 || !status || !stateOf) return false;
	const core = new Set(ring.map(keyIdentity).filter((id) => id !== undefined));
	const theirs = [...checks.log.map((key) => keyIdentity(key) ?? ""), ...status, ...stateOf];
	return theirs.every((id) => id !== "" && !core.has(id));
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
 * deleted. The checks are copied before anything is awaited. A refusal the log's objects gave stays
 * with the change, and a status or stateOf older than one read before for it is `stale`, so no older
 * object, nor a source made again, undoes what was read.
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
	| { readonly error: KeyChangeError }
	| { readonly retry: KeyChangeRetry; readonly receipt: Receipt }
> {
	const given = options.checks;
	if (given?.level !== "L0" && given?.level !== "log") return { error: "checks" };
	const checks: KeyChangeChecks =
		given.level === "L0"
			? { level: "L0" }
			: {
					level: "log",
					log: [...given.log],
					statusSigners: given.statusSigners,
					stateOfSigners: given.stateOfSigners,
					maxAge: given.maxAge,
					now: given.now,
					skew: given.skew,
					...(given.status === undefined ? {} : { status: given.status }),
					...(given.stateOf === undefined ? {} : { stateOf: given.stateOf }),
				};
	const ring = [...options.ring];
	if (checks.level === "log" && !inputsHold(checks, ring)) return { error: "checks" };
	const want = await waited(source);
	if (!want) return { error: "source" };
	const opened = await openCompletion(sealed, {
		keys: options.keys,
		ring,
		aad: utf8(hpke.completionAad(want.purpose, want.h)),
	});
	if ("error" in opened) return opened;
	const parsed = payloads.completions.keyChange.safeParse(opened.payload);
	if (!parsed.success) return { error: "payload" };
	const done = parsed.data;
	if (done.iss !== options.issuer) return { error: "issuer" };
	if (done.purpose !== want.purpose) return { error: "purpose" };
	if (!sameChange(done.change, want.change)) return { error: "change" };
	if (checks.level === "L0") return { change: done.change };

	const name = `${want.purpose}|${want.h}|${want.change.op}|${want.change.credential_id}`;
	const before = seen.get(name) ?? { statusVersion: 0, stateOfPosition: 0 };
	if (before.refused) return { error: before.refused };
	const refuse = (error: KeyChangeError) => {
		if (final.includes(error)) seen.set(name, { ...before, refused: error });
		return { error };
	};

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
	if (status.version < before.statusVersion) return { retry: "stale", receipt };
	const shard = Object.hasOwn(status.shards, receipt.shard)
		? status.shards[receipt.shard]
		: undefined;
	if (!shard || receipt.n > shard.watermark) return { retry: "notYetChecked", receipt };
	seen.set(name, { ...before, statusVersion: status.version });
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
	if (at.position < before.stateOfPosition) return { retry: "stale", receipt };
	if (at.position < receipt.position) return { retry: "stateBehind", receipt };
	seen.set(name, { ...before, statusVersion: status.version, stateOfPosition: at.position });
	const result = at.results[receipt.position - 1];
	const verdicts: readonly string[] = ["verified", "unsupported"];
	if (result?.id !== receipt.id || !verdicts.includes(result.verdict) || result.outcome !== "took")
		return refuse("result");
	const held = credentialsOf(at.state);
	if (held === undefined) return refuse("state");
	if (held.includes(want.change.credential_id) !== (want.change.op === "add")) return refuse("key");
	return { change: done.change, receipt };
}

/** A key change's completion on the screen, at the level the caller names. */
export const keyChanges = Object.freeze({ read });
