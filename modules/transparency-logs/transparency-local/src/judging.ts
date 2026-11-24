import {
	type Checks,
	type Context,
	emptyState,
	type FlowEntry,
	type FlowState,
	fold,
	judge,
} from "@mod/authority-rules";
import type { LogRecord, Preimage } from "@mod/transparency-wire";

/** The one monitor key a record names: t0 seals a preimage to no monitor, keeping it in the Core. */
export const localKey = "local";

/** A Core writer's record judged on its flow's judged prefix: its entry, with its finding. */
export type Judging = (
	record: Extract<LogRecord, { readonly position: number }>,
	preimage: Preimage,
	prior: readonly FlowEntry[],
) => Promise<FlowEntry>;

const own = <T>(items: Readonly<Record<string, T>>, id: string) =>
	Object.hasOwn(items, id) ? items[id] : undefined;

/** The first-trust key an item of the state rests on: the first of its chain, or a key with none itself. */
function rootOf(state: FlowState, id: string): string | undefined {
	const key = own(state.keys, id);
	if (key) return key.chain[0] ?? id;
	return (own(state.approvals, id) ?? own(state.families, id))?.chain[0];
}

/**
 * j0: `authority-rules`' judgment, run in the Core as each record is placed, its preimage opened as
 * the Core holds it and sealed to the local key alone. A record acceptable by the rules is forged
 * still where the credential of a root it names is no key passkeys holds for the flow's subject.
 */
export function localJudging(p: {
	readonly checks: Checks;
	readonly context: Context;
	readonly holds: (credential: string, subject: string) => Promise<boolean>;
}): Judging {
	return async (record, preimage, prior) => {
		const state = prior.reduce(
			(s, e) => fold(s, e.envelope, e.changes, e.judgment),
			emptyState as FlowState,
		);
		const ruling = judge({
			record,
			opening: { opened: preimage },
			keySets: { ever: [localKey], atRecord: [localKey] },
			state,
			prior,
			checks: p.checks,
			context: p.context,
		});
		// No version is named and every preimage opens here, so the rules never wait.
		if ("wait" in ruling)
			throw new TypeError(`transparency-local: the rules wait (${ruling.wait})`);
		const { entry } = ruling;
		const { verdict } = entry.judgment;
		if (verdict !== "verified" && verdict !== "unsupported") return entry;
		const roots = [preimage.parent, preimage.root].flatMap((id) => {
			const root = id === undefined ? undefined : rootOf(state, id);
			const credential = root === undefined ? undefined : own(state.keys, root)?.credential;
			return credential === undefined ? [] : [credential];
		});
		for (const credential of roots) {
			if (!(await p.holds(credential, record.flow.id)))
				return { ...entry, judgment: { verdict: "forged", outcome: "didNotTake" } };
		}
		return entry;
	};
}
