import { type Changes, type Finding, type FlowState, fold } from "@mod/authority-rules";
import type { Json } from "@mod/store";
import fc from "fast-check";
import { expect, it } from "vitest";
import type { Stage, Transparency } from "../src/contract.ts";
import { transparencyOver } from "../src/driver/driver.ts";
import { memoryFrames } from "./fixtures/frames.ts";
import { logBook } from "./fixtures/log.ts";
import {
	allParts,
	issue,
	keyChange,
	keyStage,
	owners,
	type Reservation,
	reservationRecord,
	seeded,
} from "./fixtures/registrations.ts";

const flow = { of: "subject", id: "s1" } as const;
const leaseMs = 5000;
const bundleEff: Changes = { family: { approval: "a1" } };
const findings: readonly Finding[] = [
	{ verdict: "verified", outcome: "took" },
	{ verdict: "verified", outcome: "took" },
	{ verdict: "held", outcome: "took" },
	{ verdict: "verified", outcome: "didNotTake" },
];
type Intent = {
	op: string;
	kind: string;
	state: string;
	by: string;
	leaseEnd: number;
	prev: number;
} | null;

/** Step023 and RegAbandon023's events on three replicas, in the order fast-check draws them. */
function world() {
	const store = memoryFrames(allParts);
	const log = logBook(store.clock.now);
	for (const [part, value] of Object.entries(seeded)) {
		store.put(flow, { part, name: "state" }, value as unknown as Json);
	}
	const names = ["w1", "w2", "w3"] as const;
	const replicas = names.map((name) =>
		transparencyOver({
			frames: store.frames,
			log: log.as(name),
			kinds: [issue, keyChange],
			owners,
			leaseMs,
		}),
	);
	const effOf = new Map<string, Changes>();
	const delivered = new Set<string>();
	let ops = 0;
	const frame = () =>
		(store.value(flow) ?? { applied: 0, intent: null }) as { applied: number; intent: Intent };
	const reservation = () =>
		store.value(flow, reservationRecord) as unknown as Reservation | undefined;

	/** What the owners' records hold, as one state. */
	const held = () =>
		Object.assign(
			{},
			...allParts
				.filter((p) => p !== "reservations")
				.map((part) => store.value(flow, { part, name: "state" })),
		) as FlowState;
	/** StateOf(applied): the same fold over the log's records, their changes as their writers left them. */
	function expected(applied: number): FlowState {
		let state = Object.assign({}, ...Object.values(seeded)) as FlowState;
		const placed = log.records(flow);
		for (const p of placed.slice(0, applied)) {
			const r = p.record;
			let e: Changes = p.changes ?? {};
			if (r.writer.role === "core" && r.kind === "abandonment") {
				const bundle = placed.find(
					(q) => q.record.kind === "bundle" && q.record.op === r.abandons?.op,
				);
				const made = bundle && bundle.record.position < r.position;
				e = made ? { abandon: bundle.record.id } : {};
			} else if (r.writer.role === "core") e = effOf.get(r.op) ?? {};
			if (!p.finding) throw new Error(`position ${r.position} taken in unjudged`);
			state = fold(state, { ...r, kind: r.kind }, e, p.finding);
		}
		return state;
	}

	async function act(event: number, who: number, pick: number) {
		const w = replicas[who % 3] as Transparency;
		const me = names[who % 3];
		const it = frame().intent;
		switch (event % 7) {
			case 0: {
				ops += 1;
				const op = `o${ops}`;
				const key = pick % 2 === 1;
				const eff = key ? { key: { credential: `c${op}`, publicKey: `p${op}` } } : bundleEff;
				effOf.set(op, eff);
				if (key) {
					const r: Reservation = {
						version: op,
						state: "verified",
						credential: `c${op}`,
						publicKey: `p${op}`,
					};
					const changed = await w.changeHeld({
						flow,
						records: [reservationRecord],
						change: () => [{ value: r as unknown as Json }],
					});
					if (!("changed" in changed)) return;
				}
				await w.decide({
					kind: key ? "key" : "issue",
					flow,
					op,
					decide: (_s, recs) =>
						key && (recs[0] as unknown as Reservation)?.version !== op
							? { refused: "notReserved" }
							: { digest: `d${op}`, eff, records: key ? [undefined] : [] },
				});
				return;
			}
			case 1: {
				// Whoever holds the intent sends its stage; a lease-less one is refused.
				if (it?.state !== "pending") return;
				const owner = replicas[names.indexOf(it.by as (typeof names)[number])] as Transparency;
				const r = reservation();
				const stage: Stage =
					it.kind === "key" && r
						? keyStage(flow, r)
						: {
								kind: "bundle",
								flow,
								op: it.op,
								stage: 1,
								last: true,
								tokens: [{ frame: "accessToken", digest: "A".repeat(43) }],
								preimage: { v: 1, evidence: [], content: { via: "code" } },
							};
				await owner.send({ flow, op: it.op, stage, prev: it.prev });
				return;
			}
			case 2: {
				const unjudged = log.records(flow).filter((p) => !p.finding);
				const p = unjudged[pick % Math.max(unjudged.length, 1)];
				if (p) log.judge(flow, p.record.position, findings[pick % findings.length] as Finding);
				return;
			}
			case 3: {
				// Half the time the intent's holder steps in its apply phase.
				const holder = it && pick % 2 === 0 ? names.indexOf(it.by as (typeof names)[number]) : -1;
				const stepper = holder >= 0 ? (replicas[holder] as Transparency) : w;
				const own = it && (holder >= 0 || it.by === me) ? it.op : undefined;
				const next = await stepper.step(own ? { flow, own } : { flow });
				if (
					"end" in next &&
					next.end?.owner &&
					next.end.ending === "took" &&
					next.end.kind === "issue"
				)
					delivered.add(next.end.op);
				return;
			}
			case 4:
				await w.tend(flow);
				return;
			case 5:
				store.clock.set(store.clock.now() + (pick % 4) * 2000);
				return;
			default:
				log.monitor(
					flow,
					pick % 2 === 0 ? "confirmation" : "denial",
					pick % 2 === 0 ? {} : { revoke: "k1" },
				);
		}
	}

	/** The models' safety invariants, at every state. */
	function check() {
		const { applied, intent } = frame();
		expect(applied).toBeLessThanOrEqual(log.records(flow).length);
		expect(held()).toEqual(expected(applied)); // KP-06
		if (intent?.state === "abandoning")
			expect(store.clock.now()).toBeGreaterThanOrEqual(intent.leaseEnd); // ClaimExclusive
		for (const p of log.records(flow)) {
			if (p.record.kind === "abandonment")
				expect(delivered.has(p.record.abandons?.op ?? "")).toBe(false); // KP-13
		}
		const r = reservation();
		if (r?.state === "active") {
			const key = log
				.records(flow)
				.find((p) => p.record.op === r.version && p.record.kind === "keyChange");
			expect(key && key.record.position <= applied && key.finding?.outcome === "took").toBe(true); // RegAgree
		}
	}

	/** Fair runs end every intent and take every record in (KP-05b, c, d). */
	async function settle() {
		store.clock.set(store.clock.now() + 3 * leaseMs);
		for (let round = 0; round < 30; round++) {
			for (const p of log.records(flow)) {
				if (!p.finding)
					log.judge(flow, p.record.position, { verdict: "verified", outcome: "took" });
			}
			for (const w of replicas) await w.tend(flow);
			const { applied, intent } = frame();
			const open = intent?.state === "pending" || intent?.state === "abandoning";
			if (applied === log.records(flow).length && !open) return true;
			check();
		}
		return false;
	}
	return { act, check, settle, frame };
}

it("keeps the models' invariants on every interleaving, and ends every intent on a fair run", async () => {
	const event = fc.tuple(fc.nat(6), fc.nat(2), fc.nat(11));
	await fc.assert(
		fc.asyncProperty(fc.array(event, { maxLength: 50 }), async (events) => {
			const w = world();
			for (const [e, who, pick] of events) {
				await w.act(e, who, pick);
				w.check();
			}
			expect(await w.settle()).toBe(true);
		}),
		{ numRuns: 300 },
	);
});
