import { createPublicKey, verify, type webcrypto } from "node:crypto";
import type { Keys } from "@mod/keys";
import { continuation, type SigningKey } from "@mod/sdk-core-wire";
import type {
	ApprovalStore,
	Continued,
	ItemsOf,
	KeptCreation,
	LastContinuation,
	StepResult,
} from "../contract.ts";
import {
	current,
	itemsIn,
	recordOf,
	type StatementRecord,
	sha256,
	stored,
} from "../statement/statement.ts";

/** Whether `signature` (ES256, r‖s, base64url) is the screen's over `input`. */
function signedBy(key: SigningKey, input: string, signature: string): boolean {
	try {
		const publicKey = createPublicKey({ key: key as webcrypto.JsonWebKey, format: "jwk" });
		const bytes = Buffer.from(signature, "base64url");
		return verify(
			"sha256",
			Buffer.from(input, "utf8"),
			{ key: publicKey, dsaEncoding: "ieee-p1363" },
			bytes,
		);
	} catch {
		return false;
	}
}

/** The purposes whose ceremony goes on by continuations: a creation's, its registration. */
const continued = new Set(["creation"]);

/** How long a call that took a continuation's step holds it, in ms: past it, the same continuation runs the step again. */
const claimMs = 30_000;

/** The most a continuation's body holds, in UTF-8 bytes: what `front-core-wire`'s `continue` carries. */
const maxBodyBytes = 8192;

/** A signature's one spelling: 64 bytes (`r‖s`), base64url without padding, its last bits zero. */
const canonicalSignature = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** Continuations: each the next sequence number, verified and taken in one write, its step run by one call and its answer kept. */
export function continuationsOver(p: {
	readonly keys: Pick<Keys, "verify">;
	readonly store: ApprovalStore;
	readonly now: () => number;
	readonly token: () => string;
}) {
	/**
	 * Takes the step of continuation `seq` for this call, in one write: the next number, once the last
	 * one's answer is kept; or the same one again, where its answer is not kept and no call holds it.
	 */
	const claim = async (
		hash: string,
		seq: number,
		body: string,
		sent: NonNullable<StatementRecord["sent"]>,
		by: string,
	) => {
		const changed = await p.store.change(hash, (current) => {
			const now = recordOf(current);
			if (!now) return undefined;
			const claimed = { by, until: p.now() + claimMs };
			const next = now.seq === seq - 1 && (now.seq === 0 || now.result !== undefined);
			if (next) {
				// The body and signature as sent are written with the number they took, never again for it.
				const { result: _kept, ...rest } = now;
				return { value: stored({ ...rest, seq, body, sent, claimed }) };
			}
			const free = now.claimed === undefined || now.claimed.until < p.now();
			const same = now.seq === seq && now.body === body && now.result === undefined;
			return same && free ? { value: stored({ ...now, claimed }) } : undefined;
		});
		return recordOf(changed?.after);
	};

	/** Keeps the step's answer where this call still holds the continuation. */
	const kept = async (hash: string, seq: number, by: string, result: StepResult) => {
		const changed = await p.store.change(hash, (current) => {
			const now = recordOf(current);
			if (now?.seq !== seq || now.claimed?.by !== by) return undefined;
			const { claimed: _done, ...rest } = now;
			return { value: stored({ ...rest, result: result as StatementRecord["result"] }) };
		});
		return recordOf(changed?.after);
	};

	const run = async (q: {
		readonly hash: string;
		readonly seq: number;
		readonly body: string;
		readonly signature: string;
		readonly step: (kept: KeptCreation) => Promise<StepResult>;
	}): Promise<Continued> => {
		const r = recordOf(await p.store.read(q.hash));
		if (!r) return { kind: "refused", reason: "unknown" };
		if (!continued.has(r.purpose)) return { kind: "refused", reason: "purpose" };
		if (Buffer.byteLength(q.body, "utf8") > maxBodyBytes)
			return { kind: "refused", reason: "body" };
		if (!canonicalSignature.test(q.signature)) return { kind: "refused", reason: "signature" };
		const body = sha256(q.body);
		if (!signedBy(r.e_sig, continuation.of("register", q.hash, q.seq, body), q.signature))
			return { kind: "refused", reason: "signature" };
		const answered = (x: StatementRecord | undefined, again: boolean): Continued | undefined =>
			x?.seq === q.seq && x.body === body && x.result !== undefined
				? { kind: "continued", seq: q.seq, again, result: x.result }
				: undefined;
		const before = answered(r, true);
		if (before) return before;
		if (r.seq !== q.seq && p.now() > r.exp) return { kind: "refused", reason: "expired" };
		const by = p.token();
		const held = await claim(q.hash, q.seq, body, { body: q.body, signature: q.signature }, by);
		if (held?.claimed?.by !== by) {
			const now = recordOf(await p.store.read(q.hash));
			const same = now?.seq === q.seq && now.body === body;
			return answered(now, true) ?? { kind: "refused", reason: same ? "pending" : "seq" };
		}
		// A creation, the one purpose continued: its items read from its bytes, the screen's keys from its record.
		const result = await q.step({
			items: itemsIn(r.jws, "creation") as ItemsOf["creation"],
			screen: { eEnc: r.e_enc, eSig: r.e_sig },
		});
		const after = await kept(q.hash, q.seq, by, result);
		return (
			answered(after, r.seq === q.seq) ??
			answered(recordOf(await p.store.read(q.hash)), true) ?? { kind: "refused", reason: "pending" }
		);
	};

	/** A creation's last continuation as taken, with what its step answered, in one read. */
	async function continuationOf(hash: string): Promise<LastContinuation | undefined> {
		const r = recordOf(await p.store.read(hash));
		if (r?.purpose !== "creation" || r.sent === undefined || p.now() > r.exp) return undefined;
		if (!(await current(p.keys, r.jws))) return undefined;
		const { body, signature } = r.sent;
		return { seq: r.seq, body, signature, ...(r.result === undefined ? {} : { result: r.result }) };
	}

	return { continue: run, continuationOf };
}
