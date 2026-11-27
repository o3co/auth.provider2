import {
	abandonedFamily,
	type Changes,
	type Finding,
	type FlowState,
	fold,
} from "@mod/authority-rules";
import { isUnavailable, Unavailable } from "@mod/kernel";
import fc from "fast-check";
import { expect, it } from "vitest";
import type { FrameStore, Json, Stage, Transparency, TransparencyLog } from "../src/contract.ts";
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

// The 0.23 checks (模型が狭めている所): the models send one stage at once, hold one record in flight
// and lose no answer. Here every frame read and write and every log call waits on fast-check's
// scheduler, so a stage lands after a Mark, a lease's end or another record; an append's answer
// is lost, its stage placed or not; and an issuing op may be a start, then its bundle. The
// invariants are those of `model.properties.test.ts`, the card's, checked whenever the run is still.

const flow = { of: "subject", id: "s1" } as const;
const leaseMs = 5000;
const findings: readonly Finding[] = [
	{ verdict: "verified", outcome: "took" },
	{ verdict: "verified", outcome: "took" },
	{ verdict: "held", outcome: "took" },
	{ verdict: "verified", outcome: "didNotTake" },
];
const names = ["w1", "w2", "w3"] as const;
type Name = (typeof names)[number];
type Loss = "placed" | "unplaced";
type Intent = {
	op: string;
	kind: string;
	state: string;
	by: string;
	leaseEnd: number;
	prev: number;
	eff: Changes | null;
} | null;

/**
 * The paths a run reached, counted so a property is never true of runs that reach none of them. A
 * bundle sent again past a record between its stages, and a key record landing after a Mark, are
 * drawn too but rarely; the driver's fixed tests hold them.
 */
const paths = [
	"landedLate",
	"lostUnplaced",
	"lostPlaced",
	"twoInFlight",
	"lateTakenIn",
	"familyMade",
	"familyAbandoned",
	"decidedAgain",
	"start",
	"abandonment",
	"keyChange",
] as const;
type Reached = Record<(typeof paths)[number], number>;
const none = (): Reached => Object.fromEntries(paths.map((p) => [p, 0])) as Reached;

function world(s: fc.Scheduler, reached: Reached) {
	const store = memoryFrames(allParts);
	const log = logBook(store.clock.now);
	for (const [part, value] of Object.entries(seeded)) {
		store.put(flow, { part, name: "state" }, value as unknown as Json);
	}
	let scheduling = true;
	/** A call that waits its turn on the scheduler, before it reaches the store or the log. */
	const later =
		<A extends unknown[], T>(label: string, f: (...a: A) => Promise<T>) =>
		async (...a: A): Promise<T> => {
			if (scheduling) await s.schedule(Promise.resolve(), label);
			return f(...a);
		};
	/** What each op's decision wrote as its eff, taken from the write that decided it, kept after. */
	const effOf = new Map<string, Changes>();
	/** The keys each op was decided on: its re-check passes while they are the same, a pure re-check. */
	const keysAt = new Map<string, string>();
	const keysOf = (state: FlowState) => JSON.stringify(Object.keys(state.keys ?? {}).sort());
	const failures: unknown[] = [];
	const frames: FrameStore = {
		...store.frames,
		read: later("read", store.frames.read),
		write: async (read, next, deadline) => {
			if (scheduling) await s.schedule(Promise.resolve(), "write");
			const before = frame().intent;
			const frame0 = frame().applied;
			const answer = await store.frames.write(read, next, deadline);
			const it = (next.frame as { intent?: Intent } | undefined)?.intent;
			if (answer !== "written" || !it) return answer;
			const open = before?.state === "pending" || before?.state === "abandoning";
			// A record that landed late, taken in by this Step.
			const applied = (next.frame as { applied?: number }).applied ?? 0;
			if (applied > frame0 && lateAt.has(applied)) reached.lateTakenIn += 1;
			if (!(open && before?.op === it.op)) {
				if (it.state === "pending" && it.eff) {
					effOf.set(it.op, it.eff);
					keysAt.set(it.op, keysOf(held()));
				}
			} else if (it.state === "pending" || it.state === "abandoning") {
				// A takeover, a Mark, a rebase or a Step keeps the decided eff as it was, while the intent is open.
				if (JSON.stringify(it.eff) !== JSON.stringify(effOf.get(it.op)))
					failures.push(new Error(`${it.op}'s eff changed by a write of its open intent`));
			}
			return answer;
		},
	};
	let inFlight = 0;
	/** Whether a family was made, and one abandoned by an abandonment taken in, this run. */
	let made = false;
	let dropped = false;
	/** The positions of the records that landed late. */
	const lateAt = new Set<number>();
	/**
	 * A replica's log for one act: the act loses one append's answer where told, and its appends stay in
	 * flight `flight` more turns past their own, so their stage lands late.
	 */
	const logOf = (name: Name, act: { loss?: Loss; flight: number }): TransparencyLog => {
		const l = log.as(name);
		let loss = act.loss;
		return {
			...l,
			head: later("head", l.head),
			of: later("of", l.of),
			at: later("at", l.at),
			append: async (stage, prev) => {
				const lost = loss;
				loss = undefined;
				if (lost === "unplaced") {
					reached.lostUnplaced += 1;
					throw new Unavailable("log");
				}
				inFlight += 1;
				if (inFlight > 1) reached.twoInFlight += 1;
				let answer: Awaited<ReturnType<TransparencyLog["append"]>>;
				try {
					for (let i = 0; scheduling && i < act.flight; i++)
						await s.schedule(Promise.resolve(), "flight");
					if (scheduling) await s.schedule(Promise.resolve(), "append");
					// Read right before the call reaches the log: a longer log after it is this append's record.
					const length = log.records(flow).length;
					answer = await l.append(stage, prev);
					// A new record of the op its sender held, placed once that op was marked: it landed late.
					const it = frame().intent;
					const placedNow = log.records(flow).length > length;
					if (
						placedNow &&
						stage.kind !== "abandonment" &&
						it?.op === stage.op &&
						it.state === "abandoning"
					) {
						reached.landedLate += 1;
						lateAt.add(log.records(flow).length);
					}
				} finally {
					inFlight -= 1;
				}
				if (lost === "placed") {
					if (answer.result === "accepted") reached.lostPlaced += 1;
					throw new Unavailable("log");
				}
				return answer;
			},
		};
	};
	/** A replica for one act: the driver holds nothing between calls, so each act may have its own. */
	const replica = (name: Name, act: { loss?: Loss; flight: number } = { flight: 0 }) =>
		transparencyOver({
			frames,
			log: logOf(name, act),
			kinds: name === "w3" ? [issue] : [issue, keyChange],
			owners,
			leaseMs,
		});
	/** `out`: the positions of the bundles whose owner answered took. */
	const delivered = new Set<number>();
	/** How many stages each issuing op has: a bundle alone, or a start and then its bundle. */
	const stagesOf = new Map<string, 1 | 2>();
	const issues: string[] = [];
	let ops = 0;
	const frame = () =>
		(store.value(flow) ?? { applied: 0, intent: null }) as { applied: number; intent: Intent };
	const reservation = () =>
		store.value(flow, reservationRecord) as unknown as Reservation | undefined;
	const held = () =>
		Object.assign(
			{},
			...allParts
				.filter((p) => p !== "reservations")
				.map((part) => store.value(flow, { part, name: "state" })),
		) as FlowState;
	/** StateOf(applied): the fold over the log's records; an op's eff with its last stage alone. */
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
			} else if (r.writer.role === "core") e = r.last ? (effOf.get(r.op) ?? {}) : {};
			if (!p.finding) throw new Error(`position ${r.position} taken in unjudged`);
			// An abandonment that drops a family the state held: present before its fold, gone after.
			const gone = "abandon" in e ? String(e.abandon) : undefined;
			const had = gone !== undefined && gone in (state.families ?? {});
			state = fold(state, { ...r, kind: r.kind }, e, p.finding);
			if (had && gone !== undefined && !(gone in (state.families ?? {}))) dropped = true;
		}
		return state;
	}

	/** The sends each replica has in a call: its owner's apply phase (`step({own})`) waits for them. */
	const sending = new Map<Name, number>();
	const running = new Set<Promise<void>>();
	/**
	 * Runs `body` on `who`, beside its other calls, losing one append's answer where told. A send counts
	 * as the replica's own until it answers; an act stepping `own` is dropped while one is pending.
	 */
	function on(
		who: Name,
		p: { loss?: Loss | undefined; flight: number; sends?: boolean; owns?: boolean },
		body: (w: Transparency) => Promise<void>,
	) {
		if (p.owns && (sending.get(who) ?? 0) > 0) return;
		if (p.sends) sending.set(who, (sending.get(who) ?? 0) + 1);
		const run = body(replica(who, { ...(p.loss ? { loss: p.loss } : {}), flight: p.flight }))
			.catch((e: unknown) => {
				if (!isUnavailable(e)) failures.push(e);
			})
			.finally(() => {
				if (p.sends) sending.set(who, (sending.get(who) ?? 1) - 1);
				running.delete(run);
			});
		running.add(run);
	}
	const holderOf = (it: Intent) => (names.includes(it?.by as Name) ? (it?.by as Name) : undefined);

	/** Starts one event's act; it runs as the scheduler lets its calls through. */
	function act(event: number, who: number, pick: number, lose: number, flight: number) {
		const me = names[who % 3] as Name;
		const loss: Loss | undefined = lose === 1 ? "placed" : lose === 2 ? "unplaced" : undefined;
		const it = frame().intent;
		switch (event % 8) {
			case 0: {
				// An issuing op, now and then one decided again under its id with other content; or a key change.
				// The ops an empty abandonment closed, nothing else of them on the flow, may be decided again.
				const records = log.records(flow).map((p) => p.record);
				const open = issues.filter(
					(op) =>
						records.some((r) => r.abandons?.op === op) &&
						!records.some((r) => r.op === op && r.kind !== "abandonment"),
				);
				const from = open.length > 0 ? open : issues;
				const again = pick % 3 === 2 ? from[pick % Math.max(from.length, 1)] : undefined;
				if (!again) ops += 1;
				const op = again ?? `o${ops}`;
				const key = !again && pick % 2 === 1;
				const live = Object.keys(held().families);
				const rotated = live[pick % Math.max(live.length, 1)];
				const eff: Changes = key
					? { key: { credential: `c${op}`, publicKey: `p${op}` } }
					: pick % 3 === 0 && rotated
						? { rotate: rotated }
						: { family: { approval: "a1" } };
				const decider = key && who % 3 === 2 ? "w1" : me;
				on(decider, { loss, flight }, async (w) => {
					if (key) {
						const r: Reservation = {
							version: op,
							state: "verified",
							credential: `c${op}`,
							publicKey: `p${op}`,
						};
						const changed = await w.changeHeld({
							kind: "key",
							flow,
							records: [reservationRecord],
							change: () => [{ value: r as unknown as Json }],
						});
						if (!("changed" in changed)) return;
					}
					const decided = await w.decide({
						kind: key ? "key" : "issue",
						flow,
						op,
						decide: (_s, recs) =>
							key && (recs[0] as unknown as Reservation)?.version !== op
								? { refused: "notReserved" }
								: { digest: `d${op}${pick}`.padEnd(43, "0"), eff, records: key ? [undefined] : [] },
					});
					if ("prev" in decided) {
						// The decision's eff is the one asked, as committed.
						if (JSON.stringify(effOf.get(op)) !== JSON.stringify(eff))
							failures.push(new Error(`${op} decided with another eff than asked`));
						if (again) reached.decidedAgain += 1;
					}
					if ("prev" in decided && !key) {
						if (!again) issues.push(op);
						stagesOf.set(op, pick % 4 < 2 ? 2 : 1);
					}
				});
				return;
			}
			case 1: {
				// The holder sends its op's next stage: the start, or after it the bundle.
				if (it?.state !== "pending") return;
				const holder = holderOf(it);
				if (!holder) return;
				const r = reservation();
				const placed = log
					.records(flow)
					.filter((p) => p.record.op === it.op && p.record.kind !== "abandonment");
				const two = it.kind === "issue" && stagesOf.get(it.op) === 2;
				const bundle: Stage = {
					kind: "bundle",
					flow,
					op: it.op,
					stage: two ? 2 : 1,
					last: true,
					tokens: [{ frame: "accessToken", digest: "A".repeat(43) }],
					preimage: { v: 1, evidence: [], content: { via: "code" } },
				};
				const { tokens: _none, ...start } = {
					...bundle,
					kind: "start" as const,
					stage: 1,
					last: false,
				};
				let stage: Stage;
				let prev = it.prev;
				if (it.kind === "key" && r) stage = keyStage(flow, r);
				else if (!two || placed.length === 0) stage = two ? start : bundle;
				else if (placed.length === 1) {
					stage = bundle;
					prev = Math.max(it.prev, placed[0]?.record.position ?? 0);
				} else return;
				// Now and then the same id with other content.
				const other = pick % 5 === 0 ? { preimage: { ...stage.preimage, parent: "x" } } : {};
				on(holder, { loss, flight, sends: true }, async (w) => {
					await w.send({ flow, op: it.op, stage: { ...stage, ...other }, prev });
				});
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
				const holder = it && pick % 2 === 0 ? holderOf(it) : undefined;
				const stepper = holder ?? me;
				const own = it && (holder || it.by === me) ? it.op : undefined;
				on(stepper, { flight, owns: own !== undefined }, async (w) => {
					const next = await w.step(own ? { flow, own } : { flow });
					if (
						"end" in next &&
						next.end?.owner &&
						next.end.ending === "took" &&
						next.end.kind === "issue"
					) {
						const op = next.end.op;
						const b = log
							.records(flow)
							.find((p) => p.record.kind === "bundle" && p.record.op === op);
						if (!b) throw new Error(`${op} took with no bundle placed`);
						delivered.add(b.record.position);
					}
				});
				return;
			}
			case 4:
				on(me, { loss, flight }, async (w) => {
					await w.tend(flow);
				});
				return;
			case 5:
				store.clock.set(store.clock.now() + (pick % 4) * 2000);
				return;
			case 6: {
				// The holder of an issuing op whose bundle met a record between its stages moves on to the head.
				const holder = it?.state === "pending" && it.kind === "issue" ? holderOf(it) : undefined;
				if (!holder || !it) return;
				on(holder, { flight }, async (w) => {
					await w.rebase({
						flow,
						op: it.op,
						recheck: (state) => keysOf(state) === keysAt.get(it.op),
					});
				});
				return;
			}
			default:
				log.monitor(
					flow,
					pick % 2 === 0 ? "confirmation" : "denial",
					pick % 2 === 0 ? {} : { revoke: "k1" },
				);
		}
	}

	/** The models' safety invariants, whenever no call is between its steps. */
	function check() {
		if (failures.length > 0) throw failures[0];
		if (Object.keys(held().families).length > 0) made = true;
		const { applied, intent } = frame();
		const records = log.records(flow);
		expect(applied).toBeLessThanOrEqual(records.length);
		expect(held()).toEqual(expected(applied)); // KP-06
		if (intent?.state === "abandoning")
			expect(store.clock.now()).toBeGreaterThanOrEqual(intent.leaseEnd); // ClaimExclusive
		// KP-13 in Step023's form: no abandonment abandons a delivered bundle of its op placed before it.
		for (const n of records) {
			if (n.record.kind !== "abandonment") continue;
			const op = n.record.abandons?.op;
			const before = records.filter(
				(q) =>
					q.record.kind === "bundle" && q.record.op === op && q.record.position < n.record.position,
			);
			expect(before.filter((q) => delivered.has(q.record.position))).toEqual([]);
		}
		const r = reservation();
		if (!r) return;
		const inApplied = (p: (typeof records)[number]) => p.record.position <= applied;
		const key = records.find((p) => p.record.op === r.version && p.record.kind === "keyChange");
		const verdict = key?.finding?.verdict;
		const took =
			key !== undefined &&
			inApplied(key) &&
			(verdict === "verified" || verdict === "unsupported") &&
			key.finding?.outcome === "took";
		expect(r.state === "active").toBe(took); // RegAgree, both ways
		// Its version ended exactly where its op ended held, or abandoned by an abandonment that took.
		const heldKey = key !== undefined && inApplied(key) && verdict === "held";
		const abandoned = records.some(
			(p) =>
				p.record.kind === "abandonment" &&
				p.record.abandons?.op === r.version &&
				inApplied(p) &&
				p.finding?.verdict === "verified" &&
				p.finding.outcome === "took",
		);
		expect(r.state === "ended").toBe(heldKey || abandoned);
	}

	/** Lets `n` scheduled calls through, then lets every act run on to its next wait. */
	async function release(n: number) {
		// Each act reaches its next scheduled call only after its continuations ran.
		const still = () => new Promise((r) => setImmediate(r));
		await still();
		for (let i = 0; i < n && s.count() > 0; i++) {
			await s.waitNext(1);
			await still();
		}
	}

	/** Lets every call through, then runs on with no scheduling and no loss: a fair run ends every intent. */
	async function settle() {
		await s.waitIdle();
		scheduling = false;
		await Promise.all([...running]);
		await new Promise((r) => setImmediate(r));
		check();
		store.clock.set(store.clock.now() + 3 * leaseMs);
		for (let round = 0; round < 30; round++) {
			for (const p of log.records(flow)) {
				if (!p.finding)
					log.judge(flow, p.record.position, { verdict: "verified", outcome: "took" });
			}
			for (const name of names) await replica(name).tend(flow);
			check();
			const { applied, intent } = frame();
			const open = intent?.state === "pending" || intent?.state === "abandoning";
			if (applied === log.records(flow).length && !open) return true;
		}
		return false;
	}
	/** Counts what this run placed before its fair run. */
	function tally() {
		const rs = log.records(flow).map((p) => p.record);
		if (rs.some((r) => r.kind === "start")) reached.start += 1;
		if (rs.some((r) => r.kind === "abandonment")) reached.abandonment += 1;
		if (rs.some((r) => r.kind === "keyChange")) reached.keyChange += 1;
		if (made) reached.familyMade += 1;
		if (dropped) reached.familyAbandoned += 1;
	}
	return { act, check, release, settle, tally };
}

// One event: its kind, its replica, a pick, an answer to lose, its appends' flight and how many calls
// to let through after. Kinds weighted to the events an open intent moves by: 0 decide, 1 send,
// 2 judge, 3 step, 4 tend, 5 the clock, 6 rebase, 7 a monitor's record.
const weights = [2, 4, 3, 3, 4, 3, 1, 1];
const kind = fc.oneof(...weights.map((weight, k) => ({ arbitrary: fc.constant(k), weight })));
const event = fc.tuple(kind, fc.nat(2), fc.nat(11), fc.nat(5), fc.nat(16), fc.nat(6));

/** Runs the property over `numRuns` runs from `seed`, counting the paths they reached. */
async function runs(params: { readonly numRuns: number; readonly seed: number }) {
	const reached = none();
	await fc.assert(
		fc.asyncProperty(
			fc.scheduler(),
			fc.array(event, { maxLength: 80, size: "max" }),
			async (s, events) => {
				const w = world(s, reached);
				for (const [e, who, pick, lose, flight, n] of events) {
					w.act(e, who, pick, lose, flight);
					await w.release(n);
					w.check();
				}
				w.tally();
				expect(await w.settle()).toBe(true);
			},
		),
		params,
	);
	return reached;
}

// 2000 runs in four of 500, each on its own fixed seed: each a few seconds, and each deterministic, so a
// path one stops reaching fails only where the code changed what its runs reach, never by chance.
it.each([23, 1, 2, 3])(
	"keeps the models' invariants with records in flight, answers lost and calls overlapping, ends every intent on a fair run, and reaches every path it is there for (seed %i)",
	async (seed) => {
		const reached = await runs({ numRuns: 500, seed });
		for (const path of paths) expect(reached[path], path).toBeGreaterThan(0);
	},
	60_000,
);
