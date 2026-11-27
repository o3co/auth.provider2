import type { Written } from "@mod/authority-rules/testing";
import { expect } from "vitest";
import type { Flow, InProcess } from "../../in-process/test/in-process.ts";

/**
 * K-15 (KP_04): what a group's bad writer placed, and on which flows, so the group's last step can
 * sweep them: no record but the bad writer's is forged (an honest Core's records on those flows
 * among them), each placed record still judged as when placed, every record judged, none held, the
 * counts the steps make. Each step holds its own records to the judgments it expects.
 */

/** A judgment as the log gives it. */
export interface Judged {
	readonly verdict: string;
	readonly outcome: string;
}

const keyOf = (flow: Flow) => `${flow.of}:${flow.id}`;

/** A group's ledger of the bad writer's placements, over one Core: each one's position and its judgment as placed. */
export function ledger(core: InProcess) {
	const flows = new Map<string, Flow>();
	const whenPlaced = new Map<string, Judged | undefined>();
	/** Keeps a position the bad writer placed, with its judgment then. */
	const keep = async (flow: Flow, position: number) => {
		const at = await core.writer.at(flow, position);
		whenPlaced.set(`${keyOf(flow)}@${position}`, at?.judged);
		return at;
	};
	/** Places a record as the bad writer, kept in the ledger: its id, when the log took it and its judgment; or the log's refusal. */
	const place = async (flow: Flow, record: Written) => {
		flows.set(keyOf(flow), flow);
		const at = await core.writer.place(record);
		if ("refused" in at) return { refused: at.refused } as const;
		const held = await keep(flow, at.position);
		if (held === undefined) throw new Error(`placed at ${at.position}, read as nothing`);
		return { id: at.id, acceptedAt: held.acceptedAt, judged: held.judged };
	};
	/** Places a reset instruction as the bad writer, kept in the ledger: the positions it placed, none for one sent again or refused. */
	const reset = async (flow: Flow, instruction: string) => {
		flows.set(keyOf(flow), flow);
		const before = await core.writer.head(flow);
		const answer = await core.writer.reset(instruction);
		const head = await core.writer.head(flow);
		for (let position = before + 1; position <= head; position++) await keep(flow, position);
		return answer;
	};
	/** As `place`, for a record the log must take. */
	const placed = async (flow: Flow, record: Written) => {
		const at = await place(flow, record);
		if ("refused" in at) throw new Error(`refused: ${at.refused}`);
		return at;
	};
	/** Each flow the bad writer placed on, read whole. */
	const sweep = async () => {
		const judged = new Map<string, Judged | undefined>();
		for (const flow of flows.values()) {
			const head = await core.writer.head(flow);
			for (let position = 1; position <= head; position++) {
				const at = await core.writer.at(flow, position);
				judged.set(`${keyOf(flow)}@${position}`, at?.judged);
			}
		}
		const where = (keep: (j: Judged | undefined, at: string) => boolean) =>
			[...judged].filter(([at, j]) => keep(j, at)).map(([at]) => at);
		return {
			/** Forged records the bad writer did not place: none, the property. */
			notPlaced: where((j, at) => j?.verdict === "forged" && !whenPlaced.has(at)),
			/** Placed records not read, or read otherwise than as placed (verdict and outcome). */
			changed: [...whenPlaced]
				.filter(
					([at, then]) =>
						!judged.has(at) || JSON.stringify(judged.get(at)) !== JSON.stringify(then),
				)
				.map(([at]) => at),
			unjudged: where((j) => j === undefined),
			held: where((j) => j?.verdict === "held"),
			placed: whenPlaced.size,
			forged: where((j) => j?.verdict === "forged").length,
			records: judged.size,
		};
	};
	return { place, placed, reset, sweep };
}

const ledgers = new WeakMap<InProcess, ReturnType<typeof ledger>>();
/** The one ledger of a Core's bad writer. */
export function ledgerOf(core: InProcess) {
	const known = ledgers.get(core);
	if (known) return known;
	const made = ledger(core);
	ledgers.set(core, made);
	return made;
}

/**
 * K-15 over a Core: every flow its bad writer placed on, read whole, holds no forged record it did
 * not place, none held, none unjudged, its forged ones as judged when placed.
 */
export async function expectSwept(
	core: InProcess,
	counts: { readonly placed: number; readonly forged: number; readonly records: number },
) {
	const swept = await ledgerOf(core).sweep();
	expect(swept.notPlaced).toEqual([]);
	expect(swept.changed).toEqual([]);
	expect(swept.held).toEqual([]);
	expect(swept.unjudged).toEqual([]);
	// The counts the group's steps make: what the bad writer placed, how many of the flows' records are
	// forged, and every record on those flows, the honest Core's beside (a step that did not run, or a
	// record gone from a flow, changes them).
	expect({ placed: swept.placed, forged: swept.forged, records: swept.records }).toEqual(counts);
}
