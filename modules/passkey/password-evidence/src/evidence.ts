import type { FirstKeyEvidence } from "@mod/first-key";
import type { Users } from "@mod/users";

/** The kind's name, as it is composed and declared. */
export const kind = "password";

/** Checks awaiting their start's end, a fixed guard: the oldest past it is let go, counted failed. */
export const pendingBound = 10_000;

/** The password the screen sent, as its own item; undefined for any other shape. */
function passwordIn(items: unknown): string | undefined {
	const given =
		typeof items === "object" && items !== null && Object.hasOwn(items, "password")
			? (items as { readonly password: unknown }).password
			: undefined;
	return typeof given === "string" ? given : undefined;
}

/**
 * A first key's password evidence: the start's identifier checked through users, passed only where
 * it names the subject. Never absent: an identifier with no password is checked as one with one.
 */
export function passwordEvidence(users: Pick<Users, "verifyAsPart">): FirstKeyEvidence {
	// Each start's settling, and whether this kind passed in it: only its own pass is taken back.
	const pending = new Map<string, { readonly passed: boolean; settle(passed: boolean): void }>();
	return {
		kind,
		check: async (start, subject, items) => {
			// The same check for every identifier and every shape, so no answer tells who exists.
			const password = passwordIn(items);
			const held = await users.verifyAsPart(start.identifier, password ?? "");
			const found = held.verified;
			// A shape other than a password's fails, even where an empty password would pass.
			const passed =
				password !== undefined &&
				subject !== undefined &&
				found.kind === "user" &&
				found.user.subject === subject;
			const oldest = pending.keys().next();
			if (pending.size >= pendingBound && !oldest.done) pending.delete(oldest.value);
			pending.set(start.nonce, { passed, settle: held.settle });
			return { kind: passed ? "passed" : "failed" };
		},
		settled: async (start, _subject, outcome) => {
			const held = pending.get(start.nonce);
			pending.delete(start.nonce);
			held?.settle(outcome === "passed" && held.passed);
		},
	};
}
