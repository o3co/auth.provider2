import type { Approvals, Continued, KeptSignUp, SignUpResult } from "@mod/approvals";
import { Unavailable } from "@mod/kernel";
import type { ContinueStage, SignUpAsk, SignUpCreated } from "@mod/passkey-management";
import type { RateLimit, Window } from "@mod/rate-limit";

/**
 * A sign-up's creation asked of the key management package (its `signUpCreations`): issued, or refused
 * `revoked` where the subject was; a passing failure throws Unavailable.
 */
export interface SignUpCreations {
	create(ask: SignUpAsk): Promise<SignUpCreated>;
}

export interface SignUpParts {
	readonly approvals: Pick<Approvals, "continueSignUp" | "signUpSubject">;
	/** users' `createIdentifierless`: the subject an idempotency key names, made once. */
	readonly createIdentifierless: (key: string) => Promise<{ readonly subject: string }>;
	readonly creations: SignUpCreations;
	readonly limit: Pick<RateLimit, "hit">;
	/** Step runs counted per source in each window. */
	readonly window: Window;
	/** Step runs counted from every source together in the same window. */
	readonly total: number;
	/** Told which count a step met past its limit, before it throws: no source, no subject. */
	readonly limited: (count: "per-source" | "total") => void;
}

/** A sign-up's continuation as the route reads it: T's hash, its number, body and E_sig's signature, and its source's key. */
export interface SignUpContinuation {
	readonly hash: string;
	readonly seq: number;
	readonly body: string;
	readonly signature: string;
	readonly source: string;
}

/**
 * A sign-up's step (F1, f1-shape r3): each run counted, per source first and then, only one its source
 * still allows, from every source, so a source past its own count spends none of the total; the subject made by the ledger
 * under T's hash as its idempotency key, so a step run again makes none second; that subject kept on T
 * (the first kept answers); its creation made by the key management package. Its refusal for good,
 * `revoked`, is kept; a passing failure is thrown on (the package's Unavailable), so the step runs
 * again.
 */
export function signUpStep(p: SignUpParts) {
	return async (kept: KeptSignUp, source: string): Promise<SignUpResult> => {
		const counted = await p.limit.hit("sign-up.per-source", source, p.window);
		if (counted.kind === "limited") {
			p.limited("per-source");
			throw new Unavailable("sign-up");
		}
		const all = await p.limit.hit("sign-up.total", "all", { ...p.window, limit: p.total });
		if (all.kind === "limited") {
			p.limited("total");
			throw new Unavailable("sign-up");
		}
		const made = await p.createIdentifierless(kept.hash);
		const subject = await p.approvals.signUpSubject(kept.hash, made.subject);
		// Its sign-up began in the write that took this step: a T with none is no store's to answer.
		if (subject === undefined) throw new Unavailable("approvals");
		const created = await p.creations.create({
			tHash: kept.hash,
			subject,
			screen: kept.screen,
			since: kept.issuedAt,
		});
		return created.kind === "issued"
			? { creation: created.statement }
			: { refused: created.reason };
	};
}

/** A T's sign-up continued: `approvals`' `continueSignUp` running the step above. */
export function signUpsOver(p: SignUpParts) {
	const step = signUpStep(p);
	return (q: SignUpContinuation) =>
		p.approvals.continueSignUp({
			hash: q.hash,
			seq: q.seq,
			body: q.body,
			signature: q.signature,
			step: (kept) => step(kept, q.source),
		});
}

/**
 * `/continue`'s stage `sign-up` (continuation-wire's word), contributed to passkey-management's
 * `continueStages`: T's sign-up continued, its creation answered as a statement, any refusal by its
 * reason. Another call holding its step, or a passing failure, throws, so the screen asks again.
 */
export function signUpStage(signUps: (q: SignUpContinuation) => Promise<Continued>): ContinueStage {
	return {
		stage: "sign-up",
		continue: async (q) => {
			// continuation-wire seals no sign-up: its body comes in the clear.
			if (!("body" in q)) throw new TypeError("sign-up: a sign-up sealed");
			const { hash, seq, body, signature, source } = q;
			const continued = await signUps({ hash, seq, body, signature, source });
			if (continued.kind === "refused") {
				if (continued.reason === "pending") throw new Unavailable("approvals");
				return { kind: "refused", reason: continued.reason };
			}
			const result = continued.result as { creation?: unknown; refused?: unknown } | null;
			if (typeof result?.creation === "string")
				return { kind: "statement", statement: result.creation };
			if (typeof result?.refused === "string") return { kind: "refused", reason: result.refused };
			// The step keeps one or the other: anything else is no answer this package made.
			throw new TypeError("sign-up: a sign-up kept neither a creation nor a refusal");
		},
	};
}
