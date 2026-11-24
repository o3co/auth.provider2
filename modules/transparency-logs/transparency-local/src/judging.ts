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

/** A record another writer writes (a reset boundary, the monitor's here) judged with its body on its flow's judged prefix. */
export type SignedJudging = (
	record: Extract<LogRecord, { readonly position: number }>,
	body: unknown,
	prior: readonly FlowEntry[],
) => FlowEntry;

/** j0 for a record no Core writer writes: `authority-rules`' judgment with its body. */
export function localSignedJudging(p: {
	readonly checks: Checks;
	readonly context: Context;
}): SignedJudging {
	return (record, body, prior) => {
		const state = prior.reduce(
			(s, e) => fold(s, e.envelope, e.changes, e.judgment),
			emptyState as FlowState,
		);
		const ruling = judge({ record, body, state, prior, checks: p.checks, context: p.context });
		if ("wait" in ruling)
			throw new TypeError(`transparency-local: the rules wait (${ruling.wait})`);
		return ruling.entry;
	};
}

/** A Core writer's record judged on its flow's judged prefix: its entry, with its finding. */
export type Judging = (
	record: Extract<LogRecord, { readonly position: number }>,
	preimage: Preimage,
	prior: readonly FlowEntry[],
) => Promise<FlowEntry>;

/** A client at a registry version, as the Core's registry holds it now: the keys written in its record and its own ceiling. */
export interface ClientReading {
	readonly keys: readonly unknown[];
	/** Whether its own ceiling holds the audience and the scope (space-separated), the issuer never among them. */
	ceiling(audience: string, scope: string): boolean;
}

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
	/** A client at a registry version, where the registry holds it at that version now; none otherwise. */
	readonly clientAt: (client: string, version: number) => Promise<ClientReading | undefined>;
}): Judging {
	/** A client's record's client, at its start's registry version: read now, so one at another version is unchecked. */
	async function clientOf(record: Parameters<Judging>[0], prior: readonly FlowEntry[]) {
		if (record.flow.of !== "client") return undefined;
		const start = prior.find((e) => e.envelope.op === record.op && e.envelope.kind === "start");
		const version = record.kind === "start" ? record.registryVersion : start?.client?.version;
		const read = version === undefined ? undefined : await p.clientAt(record.flow.id, version);
		return read && version !== undefined ? { ...read, version } : undefined;
	}
	return async (record, preimage, prior) => {
		const state = prior.reduce(
			(s, e) => fold(s, e.envelope, e.changes, e.judgment),
			emptyState as FlowState,
		);
		const client = await clientOf(record, prior);
		const ruling = judge({
			record,
			opening: { opened: preimage },
			keySets: { ever: [localKey], atRecord: [localKey] },
			// No publisher's flow is here: a client's start's registry version is given no bounds.
			...(record.registryVersion === undefined ? {} : { versions: { registry: { at: 0 } } }),
			...(client ? { client: { keys: client.keys } } : {}),
			state,
			prior,
			checks: client
				? {
						...p.checks,
						selfCeiling: (id, version, audience, scope) =>
							id === record.flow.id &&
							version === client.version &&
							client.ceiling(audience, scope),
					}
				: p.checks,
			context: p.context,
		});
		// No version but a client's is named, given no bounds, and every preimage opens here, so the rules never wait.
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
