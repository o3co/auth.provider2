import {
	abandonedFamily,
	type Changes,
	type Finding,
	type FlowState,
	fold,
} from "@mod/authority-rules";
import fc from "fast-check";
import { expect, it } from "vitest";
import type { Json, Stage, Transparency } from "../src/contract.ts";
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

/**
 * Step023 and RegAbandon023's events on three replicas, in the order fast-check draws them. The
 * third has no registration of the key change; an op is decided again under its id after others.
 */
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
			kinds: name === "w3" ? [issue] : [issue, keyChange],
			owners,
			leaseMs,
		}),
	);
	const effOf = new Map<string, Changes>();
	/** `out`: the positions of the bundles whose owner answered took. */
	const delivered = new Set<number>();
	const issues: string[] = [];
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
				const op = r.abandons?.op ?? "";
				const bundle = placed.find((q) => q.record.kind === "bundle" && q.record.op === op);
				const made = bundle && bundle.record.position < r.position;
				const family =
					made && abandonedFamily({ envelope: bundle.record, changes: effOf.get(op) ?? {} });
				e = family ? { abandon: family } : {};
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
				// Now and then an issuing op is decided again under its id, other ops between.
				const again = pick % 3 === 2 ? issues[pick % Math.max(issues.length, 1)] : undefined;
				if (!again) ops += 1;
				const op = again ?? `o${ops}`;
				const key = !again && pick % 2 === 1;
				// An issuing op makes a family, or rotates a live one.
				const live = Object.keys(held().families);
				const rotated = live[pick % Math.max(live.length, 1)];
				const issued = pick % 3 === 0 && rotated ? { rotate: rotated } : bundleEff;
				const made = key ? { key: { credential: `c${op}`, publicKey: `p${op}` } } : issued;
				const eff = (again && effOf.get(again)) || made;
				effOf.set(op, eff);
				if (!key && !again) issues.push(op);
				// The third replica has no key change to decide.
				const decider = key && who % 3 === 2 ? (replicas[0] as Transparency) : w;
				if (key) {
					const r: Reservation = {
						version: op,
						state: "verified",
						credential: `c${op}`,
						publicKey: `p${op}`,
					};
					const changed = await decider.changeHeld({
						kind: "key",
						flow,
						records: [reservationRecord],
						change: () => [{ value: r as unknown as Json }],
					});
					if (!("changed" in changed)) return;
				}
				await decider.decide({
					kind: key ? "key" : "issue",
					flow,
					op,
					decide: (_s, recs) =>
						key && (recs[0] as unknown as Reservation)?.version !== op
							? { refused: "notReserved" }
							: { digest: `d${op}`.padEnd(43, "0"), eff, records: key ? [undefined] : [] },
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
				// Now and then the same id with other content: once placed, the log answers sameIdOther.
				const other = pick % 3 === 0 ? { preimage: { ...stage.preimage, parent: "x" } } : {};
				await owner.send({ flow, op: it.op, stage: { ...stage, ...other }, prev: it.prev });
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
				) {
					const op = next.end.op;
					const bundle = log
						.records(flow)
						.find((p) => p.record.kind === "bundle" && p.record.op === op);
					if (!bundle) throw new Error(`${op} took with no bundle placed`);
					delivered.add(bundle.record.position);
				}
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
		// KP-13: no abandonment record abandons a delivered bundle of its op placed before it
		// (Step023's BundleOf(o, n)). A bundle placed after it belongs to the op decided again under
		// its id (RegAbandon023's Decide on ~InLogKey), which that abandonment does not abandon.
		for (const n of log.records(flow)) {
			if (n.record.kind !== "abandonment") continue;
			const op = n.record.abandons?.op;
			const before = log
				.records(flow)
				.filter(
					(q) =>
						q.record.kind === "bundle" &&
						q.record.op === op &&
						q.record.position < n.record.position,
				);
			expect(before.filter((q) => delivered.has(q.record.position))).toEqual([]);
		}
		const r = reservation();
		if (r) {
			const key = log
				.records(flow)
				.find((p) => p.record.op === r.version && p.record.kind === "keyChange");
			const verdict = key?.finding?.verdict;
			const took =
				key !== undefined &&
				key.record.position <= applied &&
				(verdict === "verified" || verdict === "unsupported") &&
				key.finding?.outcome === "took";
			expect(r.state === "active").toBe(took); // RegAgree, both ways
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
	return { act, check, settle, frame, records: () => log.records(flow), delivered };
}

it("lets an op decided again after an abandonment that abandoned nothing deliver its bundle (KP-13)", async () => {
	// fast-check's shrunk run: o1's intent outlives its lease, an empty abandonment closes it, and
	// o1 is decided again under its id; its bundle lands after the abandonment and is delivered.
	const w = world();
	const events = [
		[0, 0, 0],
		[5, 0, 3],
		[4, 0, 0],
		[4, 0, 0],
		[2, 0, 0],
		[3, 0, 0],
		[0, 0, 5],
		[1, 0, 0],
		[2, 0, 0],
		[3, 0, 0],
	] as const;
	for (const [e, who, pick] of events) {
		await w.act(e, who, pick);
		w.check();
	}
	const placed = w.records().map((p) => [p.record.kind, p.record.op, p.record.position]);
	expect(placed).toEqual([
		["abandonment", "abandonment:1:o1", 1],
		["bundle", "o1", 2],
	]);
	expect([...w.delivered]).toEqual([2]);
	expect(await w.settle()).toBe(true);
});

it("keeps the models' invariants on every interleaving, and ends every intent on a fair run", async () => {
	const event = fc.tuple(fc.nat(6), fc.nat(2), fc.nat(11));
	await fc.assert(
		fc.asyncProperty(fc.array(event, { maxLength: 50, size: "max" }), async (events) => {
			const w = world();
			for (const [e, who, pick] of events) {
				await w.act(e, who, pick);
				w.check();
			}
			expect(await w.settle()).toBe(true);
		}),
		{ numRuns: 1000 },
	);
	// A thousand runs of up to fifty events take seconds, past the default per-test time on a busy host.
}, 60_000);
