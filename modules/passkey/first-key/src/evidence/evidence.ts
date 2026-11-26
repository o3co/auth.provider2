import { type EvidenceKind, trustedNames } from "@mod/promises";
import type { FirstKeyEvidence, FirstKeyStart, StartOutcome } from "../contract.ts";
import { mailTokenBytes } from "../sizes.ts";

/** The kinds' answers taken together: passed, failed, or a kind's fault. */
export type Checked = "passed" | "failed" | "unavailable";

/** A start's evidence asked: what it came to, and the telling of the start's end to every kind asked. */
export interface Asked {
	readonly checked: Checked;
	/** What the kinds threw, for the path to write down: a fault never changes the screen's answer. */
	readonly faults: readonly unknown[];
	/**
	 * Tells each kind the start's end, once however often called: the first call's end. What the
	 * kinds threw is answered for the path to write down; a kind that throws is let be, as an end may
	 * never come.
	 */
	tell(outcome: StartOutcome): Promise<readonly unknown[]>;
}

/** Asks every kind composed of one start, in the order composed, each once. */
export interface Evidence {
	ask(
		start: FirstKeyStart,
		subject: string | undefined,
		items: Readonly<Record<string, unknown>>,
	): Promise<Asked>;
}

/** The kinds' items from the start's request as the wire carries it: its password is the kind `password`'s. */
export const itemsOf = (plain: {
	readonly password?: string | undefined;
}): Readonly<Record<string, unknown>> =>
	plain.password === undefined ? {} : { password: { password: plain.password } };

type Answer = "passed" | "failed" | "absent" | "fault";
const answers = new Set(["passed", "failed", "absent"]);

/**
 * The path's rule: with no kind composed, the inbox alone passes; else every kind that does not
 * answer `absent` passed, and one absent on every kind passes only where `inboxOnly` says so.
 */
function judged(given: readonly Answer[], inboxOnly: boolean): Checked {
	if (given.length === 0) return "passed";
	if (given.includes("fault")) return "unavailable";
	const held = given.filter((a) => a !== "absent");
	if (held.length === 0) return inboxOnly ? "passed" : "failed";
	return held.every((a) => a === "passed") ? "passed" : "failed";
}

/** A kind's answer as the contract has it: any other value is the kind's fault, never a pass. */
function read(answer: unknown): Answer {
	const kind = (answer as { kind?: unknown } | null)?.kind;
	if (typeof kind === "string" && answers.has(kind)) return kind as Answer;
	throw new TypeError("first-key: a kind answered none of passed, failed, absent");
}

export function evidenceOver(kinds: readonly FirstKeyEvidence[], inboxOnly: boolean): Evidence {
	return {
		ask: async (start, subject, items) => {
			const faults: unknown[] = [];
			const given: Answer[] = [];
			// Every kind is asked whatever another answered, so the work is alike whatever they say.
			for (const kind of kinds) {
				try {
					const own = Object.hasOwn(items, kind.kind) ? items[kind.kind] : undefined;
					given.push(read(await kind.check(start, subject, own)));
				} catch (fault) {
					faults.push(fault);
					given.push("fault");
				}
			}
			let told: Promise<readonly unknown[]> | undefined;
			const tellAll = async (outcome: StartOutcome) => {
				// Each started inside a promise, so one that throws at once leaves the rest told.
				const ends = await Promise.allSettled(
					kinds.map((kind) =>
						Promise.resolve().then(() => kind.settled?.(start, subject, outcome)),
					),
				);
				return ends.flatMap((end) => (end.status === "rejected" ? [end.reason] : []));
			};
			return {
				checked: judged(given, inboxOnly),
				faults,
				tell: (outcome) => {
					told ??= tellAll(outcome);
					return told;
				},
			};
		},
	};
}

/** The kinds composed that `promises` holds no declaration of, or holds as past. */
export function undeclared(
	composed: readonly FirstKeyEvidence[],
	declared: readonly EvidenceKind[],
): string[] {
	const living = new Set(declared.filter((k) => !k.past).map((k) => k.kind));
	return composed.map((k) => k.kind).filter((name) => !living.has(name));
}

/** The inbox's kind, the path's own: a mail token of its random bytes, living the token's lifetime, used once. */
export const inboxKind = (lifetimeMs: number, alone: boolean): EvidenceKind => ({
	kind: "inbox",
	by: "first-key",
	trusts: [trustedNames.inbox],
	strength: { kind: "secret", bits: mailTokenBytes * 8, lifetimeMs },
	...(alone ? { alone: true } : {}),
});
