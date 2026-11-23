import { type Envelope, emptyState, type FlowState, fold, ruleSchemas } from "@mod/authority-rules";
import { Unavailable } from "@mod/kernel";
import type { Flow } from "@mod/transparency-wire";
import type {
	FrameStore,
	IntentUnit,
	Json,
	OperationKind,
	PartNext,
	PartRecord,
	Placed,
	Stage,
	StateOwner,
	Transparency,
	TransparencyLog,
} from "../contract.ts";
import {
	type At,
	abandonStage,
	closedByOwner,
	decided,
	type Frame,
	frameOf,
	intentOf,
	isOpen,
	isOrphan,
	isOwner,
	marked,
	rebased,
	stepped,
	type Taken,
	takenOver,
	type Written,
	whileClosed,
} from "../frame/frame.ts";

/** How long past its read a write that is no owner's may still commit, on the store clock. */
const writeWindowMs = 10_000;
/** The records a tending takes in at most before it yields the flow. */
const tendSteps = 64;
/** How many reads find the intent's kind before contention is unavailable. */
const kindReads = 3;

/**
 * The driver: the frame's I/O around its pure core. Every event reads the frame with the owners'
 * records (and the intent's kind's), decides with the core, and writes one CAS of all it read.
 */
export function transparencyOver(p: {
	readonly frames: FrameStore;
	readonly log: TransparencyLog;
	readonly kinds: readonly OperationKind[];
	readonly owners: readonly StateOwner[];
	readonly leaseMs: number;
}): Transparency {
	const { frames, log, owners, leaseMs } = p;
	const kinds = new Map(p.kinds.map((k) => [k.name, k]));
	const bundle = (kind: string) => kinds.get(kind)?.bundle === true;
	/** The unit of a subject's flow; none for any other, which the driver does not run. */
	const unitOf = (flow: Flow): IntentUnit | undefined =>
		flow.of === "subject" ? { flow: { of: "subject", id: flow.id } } : undefined;
	const notSubject = { refused: "notSubject" } as const;
	const atNow = (now: number): At => ({
		replica: log.writer.instance,
		generation: log.writer.generation,
		now,
	});
	const named = (
		who: { readonly name: string; readonly parts: readonly string[] },
		rs: readonly PartRecord[],
	) => {
		for (const r of rs) {
			if (!who.parts.includes(r.part))
				throw new TypeError(`${who.name} names a record of part ${r.part}, not its own`);
		}
		return rs;
	};

	/** One read: the frame, every owner's records, then `extra`; the state the owners' records hold. */
	async function snapshot(unit: IntentUnit, extra: readonly PartRecord[]) {
		const owned = owners.map((o) => named(o, o.records(unit.flow)));
		const records = [...owned.flat(), ...extra];
		const keys = records.map((r) => `${r.part}\n${r.name}`);
		if (new Set(keys).size !== keys.length)
			throw new TypeError("a record is named twice in one read");
		const read = await frames.read(unit, records);
		const at = atNow(read.now);
		const frame = frameOf(read.frame, at.generation);
		let from = 0;
		const slices = owned.map((rs) => {
			from += rs.length;
			return read.held.slice(from - rs.length, from);
		});
		const parts = owners.map((o, i) => {
			const fields = o.read(slices[i] ?? []);
			return Object.fromEntries(o.holds.map((f) => [f, fields[f] ?? emptyState[f]]));
		});
		const state = ruleSchemas.flowState.parse(Object.assign({}, emptyState, ...parts));
		return { read, at, frame, slices, extra: read.held.slice(from), state };
	}
	type Snapshot = Awaited<ReturnType<typeof snapshot>>;
	/** The frame alone, and who reads it when. */
	async function frameAt(unit: IntentUnit) {
		const read = await frames.read(unit, []);
		const at = atNow(read.now);
		return { at, frame: frameOf(read.frame, at.generation) };
	}
	const kindOf = (s: { readonly frame: Frame; readonly at: At }) =>
		kinds.get(intentOf(s.frame, s.at)?.kind ?? "");
	/** An open intent of a kind this replica has no registration of: it takes in, claims and ends nothing. */
	const unregistered = (s: { readonly frame: Frame; readonly at: At }) => {
		const it = intentOf(s.frame, s.at);
		return isOpen(it) && !kinds.has(it?.kind ?? "");
	};
	/** A read with the records of the intent's kind, read again while the intent's kind moves under it. */
	async function withKind(unit: IntentUnit) {
		let kind = kindOf(await frameAt(unit));
		for (let read = 0; read < kindReads; read++) {
			const snap = await snapshot(unit, kind ? named(kind, kind.records(unit.flow)) : []);
			const now = kindOf(snap);
			if (now === kind) return { snap, kind };
			kind = now;
		}
		throw new Unavailable("transparency");
	}
	/** The one write: the frame, each owner's records, then the extra records; held before `until`. */
	async function write(
		snap: Snapshot,
		next: {
			readonly frame?: Frame;
			readonly owned?: readonly PartNext[];
			readonly extra?: readonly PartNext[];
		},
		until?: number,
	) {
		const owned = next.owned ?? snap.slices.flatMap((s) => s.map(() => undefined));
		const extra = next.extra ?? snap.extra.map(() => undefined);
		if (owned.length + extra.length !== snap.read.records.length) {
			throw new TypeError("a registration wrote another count of records than it read");
		}
		const deadline = Math.min(until ?? Number.POSITIVE_INFINITY, snap.read.now + writeWindowMs);
		return frames.write(
			snap.read,
			{
				...(next.frame ? { frame: next.frame as unknown as Json } : {}),
				records: [...owned, ...extra],
			},
			deadline,
		);
	}
	const settled = (answer: "written" | "moved" | "late") =>
		answer === "written" ? undefined : { refused: answer };
	/** A core write of the frame alone, with the end's records of its kind where it ends an op. */
	async function frameWrite(snap: Snapshot, kind: OperationKind | undefined, w: Written) {
		const extra = w.end && kind ? kind.end(w.end, snap.extra) : undefined;
		return write(snap, { frame: w.frame, ...(extra ? { extra } : {}) }, w.ownerUntil);
	}
	const takenOf = (placed: Placed): Taken => {
		const r = placed.record;
		if (!placed.finding) throw new TypeError("an unjudged record is not taken in");
		return {
			id: r.id,
			role: r.writer.role,
			kind: r.kind,
			op: r.op,
			last: r.last,
			position: r.position,
			...(r.abandons ? { abandons: r.abandons } : {}),
			finding: placed.finding,
			...(placed.changes ? { changes: placed.changes } : {}),
		};
	};

	async function step(unit: IntentUnit, own?: string) {
		const { flow } = unit;
		const { snap, kind } = await withKind(unit);
		if (unregistered(snap)) return { refused: "stuck" as const };
		const placed = await log.at(flow, snap.frame.applied + 1);
		if (!placed) return { refused: "atHead" as const };
		if (!placed.finding) return { refused: "unjudged" as const };
		const r = placed.record;
		const taken = stepped(snap.frame, snap.at, takenOf(placed), {
			own: own !== undefined && own === r.op,
			bundle,
		});
		if ("refused" in taken) return taken;
		const envelope: Envelope = {
			id: r.id,
			kind: r.kind,
			op: r.op,
			stage: r.stage,
			last: r.last,
			position: r.position,
			acceptedAt: r.acceptedAt,
		};
		// The one fold, whatever the record's kind or writer; each owner maps the result back.
		const state: FlowState = fold(snap.state, envelope, taken.changes, placed.finding);
		const owned = owners.flatMap((o, i) => {
			const slice = snap.slices[i] ?? [];
			const next = o.write(state, slice);
			if (next.length !== slice.length)
				throw new TypeError(`${o.name} wrote another count of records than it read`);
			return next;
		});
		const extra = taken.end && kind ? kind.end(taken.end, snap.extra) : undefined;
		const answer = await write(
			snap,
			{ frame: taken.frame, owned, ...(extra ? { extra } : {}) },
			taken.ownerUntil,
		);
		return settled(answer) ?? { position: r.position, ...(taken.end ? { end: taken.end } : {}) };
	}

	async function send(q: {
		readonly flow: Flow;
		readonly op: string;
		readonly stage: Stage;
		readonly prev: number;
	}) {
		const unit = unitOf(q.flow);
		if (!unit) return notSubject;
		const { snap, kind } = await withKind(unit);
		const it = intentOf(snap.frame, snap.at);
		if (!kind || !isOwner(it, snap.at) || it?.op !== q.op || q.stage.op !== q.op) {
			return { refused: "notOwner" as const };
		}
		const answer = await log.append(q.stage, q.prev);
		const first = q.stage.stage === 1 && q.prev === it.prev;
		if (answer.result !== "refused" || answer.refusal !== "prevMismatch" || !first)
			return { answer };
		// The first stage refused for good: the owner closes the op without a record.
		const closed = closedByOwner(snap.frame, snap.at, q.op);
		if ("refused" in closed || (await frameWrite(snap, kind, closed)) !== "written")
			return { answer };
		return { answer, end: closed.end };
	}

	async function claim(unit: IntentUnit) {
		const { flow } = unit;
		const { snap, kind } = await withKind(unit);
		if (unregistered(snap)) return {};
		const it = intentOf(snap.frame, snap.at);
		const head = await log.head(flow);
		if (isOrphan(it, snap.at) && it) {
			// An orphan its taker could not end is marked: taking it over again would meet the same refusal.
			const resend = it.taken ? undefined : kind?.resend?.(flow, it.op, snap.extra);
			const over = resend ? takenOver(snap.frame, snap.at, { leaseMs, bundle }) : undefined;
			if (resend && over && "frame" in over) {
				if ((await write(snap, { frame: over.frame })) !== "written") return {};
				const sent = await send({ flow, op: it.op, stage: resend, prev: it.prev });
				return { did: "tookOver" as const, ...("answer" in sent ? { answer: sent.answer } : {}) };
			}
			const mark = marked(snap.frame, snap.at, head);
			if (!("frame" in mark) || (await write(snap, { frame: mark.frame })) !== "written") return {};
			return { did: "marked" as const };
		}
		if (it?.state !== "abandoning") return {};
		const abandon = abandonStage(snap.frame, snap.at, head, await log.of(flow, it.op));
		if ("refused" in abandon) return {};
		const stage: Stage = {
			kind: "abandonment",
			flow,
			op: abandon.op,
			stage: 1,
			last: true,
			abandons: abandon.abandons,
			preimage: { v: 1, evidence: [], content: {} },
		};
		return { did: "abandonment" as const, answer: await log.append(stage, abandon.prev) };
	}

	return {
		async decide(q) {
			const kind = kinds.get(q.kind);
			if (!kind) throw new TypeError(`no kind of operation ${q.kind} is registered`);
			const unit = unitOf(q.flow);
			if (!unit) return notSubject;
			const snap = await snapshot(unit, named(kind, kind.records(q.flow)));
			const head = await log.head(q.flow);
			const placed = await log.of(q.flow, q.op);
			const guard = decided(snap.frame, snap.at, {
				op: q.op,
				kind: q.kind,
				digest: "-",
				eff: {},
				head,
				placed,
				leaseMs,
			});
			if ("refused" in guard) return guard;
			const asked = q.decide(snap.state, snap.extra);
			if ("refused" in asked) return asked;
			const next = decided(snap.frame, snap.at, {
				...asked,
				op: q.op,
				kind: q.kind,
				head,
				placed,
				leaseMs,
			});
			if ("refused" in next) return next;
			const answer = await write(snap, { frame: next.frame, extra: asked.records });
			return settled(answer) ?? { prev: snap.frame.applied };
		},
		send,
		async rebase(q) {
			const unit = unitOf(q.flow);
			if (!unit) return notSubject;
			const { snap, kind } = await withKind(unit);
			if (!kind) return { refused: "notOwner" as const };
			const head = await log.head(q.flow);
			const moved = rebased(snap.frame, snap.at, q.op, head);
			if ("refused" in moved) return moved;
			// The first stage is never put again (A16): its refusal closes the op in `send`.
			if ((await log.of(q.flow, q.op)).stages === 0) return { refused: "unplaced" as const };
			if (q.recheck(snap.state))
				return settled(await frameWrite(snap, kind, moved)) ?? { prev: head };
			const closed = closedByOwner(snap.frame, snap.at, q.op);
			if ("refused" in closed) return closed;
			const answer = await frameWrite(snap, kind, closed);
			return answer === "written" ? { end: closed.end } : { refused: answer };
		},
		async step(q) {
			const unit = unitOf(q.flow);
			return unit ? step(unit, q.own) : notSubject;
		},
		async tend(flow) {
			const unit = unitOf(flow);
			if (!unit) return notSubject;
			let count = 0;
			for (; count < tendSteps; count++) {
				const first = await frameAt(unit);
				const it = intentOf(first.frame, first.at);
				// A replica's tending is the apply phase of an op it took over.
				const own = it?.taken && isOwner(it, first.at) ? it.op : undefined;
				const next = await step(unit, own);
				if (!("position" in next)) break;
			}
			const claimed = await claim(unit);
			return { stepped: count, ...claimed };
		},
		async changeHeld(q) {
			const kind = kinds.get(q.kind);
			if (!kind) throw new TypeError(`no kind of operation ${q.kind} is registered`);
			const unit = unitOf(q.flow);
			if (!unit) return notSubject;
			const snap = await snapshot(unit, named(kind, q.records));
			const closed = whileClosed(snap.frame, snap.at);
			if ("refused" in closed) return closed;
			return settled(await write(snap, { extra: q.change(snap.extra) })) ?? { changed: true };
		},
	};
}
