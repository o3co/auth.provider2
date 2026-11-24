import { createPublicKey, verify, type webcrypto } from "node:crypto";
import { continuation, type SigningKey } from "@mod/sdk-core-wire";
import type { ApprovalStore, Continued, StepResult } from "../contract.ts";
import { recordOf, type StatementRecord, sha256, stored } from "../statement/statement.ts";

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

/** Continuations: each the next sequence number, verified and taken in one write, its step run by one call and its answer kept. */
export function continuationsOver(p: {
	readonly store: ApprovalStore;
	readonly now: () => number;
	readonly token: () => string;
}) {
	/**
	 * Takes the step of continuation `seq` for this call, in one write: the next number, once the last
	 * one's answer is kept; or the same one again, where its answer is not kept and no call holds it.
	 */
	const claim = async (hash: string, seq: number, body: string, by: string) => {
		const changed = await p.store.change(hash, (current) => {
			const now = recordOf(current);
			if (!now) return undefined;
			const claimed = { by, until: p.now() + claimMs };
			const next = now.seq === seq - 1 && (now.seq === 0 || now.result !== undefined);
			if (next) {
				const { result: _kept, ...rest } = now;
				return { value: stored({ ...rest, seq, body, claimed }) };
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

	return async (q: {
		readonly hash: string;
		readonly seq: number;
		readonly body: string;
		readonly signature: string;
		readonly step: () => Promise<StepResult>;
	}): Promise<Continued> => {
		const r = recordOf(await p.store.read(q.hash));
		if (!r) return { kind: "refused", reason: "unknown" };
		if (!continued.has(r.purpose)) return { kind: "refused", reason: "purpose" };
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
		const held = await claim(q.hash, q.seq, body, by);
		if (held?.claimed?.by !== by) {
			const now = recordOf(await p.store.read(q.hash));
			const same = now?.seq === q.seq && now.body === body;
			return answered(now, true) ?? { kind: "refused", reason: same ? "pending" : "seq" };
		}
		const result = await q.step();
		const after = await kept(q.hash, q.seq, by, result);
		return (
			answered(after, r.seq === q.seq) ??
			answered(recordOf(await p.store.read(q.hash)), true) ?? { kind: "refused", reason: "pending" }
		);
	};
}
