import { type Envelope, emptyState, type FlowState, fold, ruleSchemas } from "@mod/authority-rules";
import { Unavailable } from "@mod/kernel";
import type { Json } from "@mod/store";
import type { Flow } from "@mod/transparency-wire";
import type {
	FrameStore,
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
	// A kind no longer registered is taken for a bundle: never taken over.
	const bundle = (kind: string) => kinds.get(kind)?.bundle ?? true;
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
	async function snapshot(flow: Flow, extra: readonly PartRecord[]) {
		const owned = owners.map((o) => named(o, o.records(flow)));
		const records = [...owned.flat(), ...extra];
		const keys = records.map((r) => `${r.part}\n${r.name}`);
		if (new Set(keys).size !== keys.length)
			throw new TypeError("a record is named twice in one read");
		const read = await frames.read(flow, records);
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
	async function frameAt(flow: Flow) {
		const read = await frames.read(flow, []);
		const at = atNow(read.now);
		return { at, frame: frameOf(read.frame, at.generation) };
	}
	const kindOf = (s: { readonly frame: Frame; readonly at: At }) =>
		kinds.get(intentOf(s.frame, s.at)?.kind ?? "");
	/** A read with the records of the intent's kind, read again while the intent's kind moves under it. */
	async function withKind(flow: Flow) {
		let kind = kindOf(await frameAt(flow));
		for (let read = 0; read < kindReads; read++) {
			const snap = await snapshot(flow, kind ? named(kind, kind.records(flow)) : []);
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

	async function step(flow: Flow, own?: string) {
		const { snap, kind } = await withKind(flow);
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
		const { snap, kind } = await withKind(q.flow);
		const it = intentOf(snap.frame, snap.at);
		if (!isOwner(it, snap.at) || it?.op !== q.op || q.stage.op !== q.op) {
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

	async function claim(flow: Flow) {
		const { snap, kind } = await withKind(flow);
		const it = intentOf(snap.frame, snap.at);
		const head = await log.head(flow);
		if (isOrphan(it, snap.at) && it) {
			const resend = kind?.resend?.(flow, it.op, snap.extra);
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
		const abandon = abandonStage(snap.frame, snap.at, head);
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
			const snap = await snapshot(q.flow, named(kind, kind.records(q.flow)));
			const head = await log.head(q.flow);
			const guard = decided(snap.frame, snap.at, {
				op: q.op,
				kind: q.kind,
				digest: "-",
				eff: {},
				head,
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
				leaseMs,
			});
			if ("refused" in next) return next;
			const answer = await write(snap, { frame: next.frame, extra: asked.records });
			return settled(answer) ?? { prev: snap.frame.applied };
		},
		send,
		async rebase(q) {
			const { snap, kind } = await withKind(q.flow);
			const head = await log.head(q.flow);
			const moved = rebased(snap.frame, snap.at, q.op, head);
			if ("refused" in moved) return moved;
			if (q.recheck(snap.state))
				return settled(await frameWrite(snap, kind, moved)) ?? { prev: head };
			const closed = closedByOwner(snap.frame, snap.at, q.op);
			if ("refused" in closed) return closed;
			const answer = await frameWrite(snap, kind, closed);
			return answer === "written" ? { end: closed.end } : { refused: answer };
		},
		step: (q) => step(q.flow, q.own),
		async tend(flow) {
			let count = 0;
			for (; count < tendSteps; count++) {
				const first = await frameAt(flow);
				const it = intentOf(first.frame, first.at);
				// A replica's tending is the apply phase of an op it took over.
				const own = it?.taken && isOwner(it, first.at) ? it.op : undefined;
				const next = await step(flow, own);
				if (!("position" in next)) break;
			}
			const claimed = await claim(flow);
			return { stepped: count, ...claimed };
		},
		async changeHeld(q) {
			const snap = await snapshot(q.flow, q.records);
			const closed = whileClosed(snap.frame, snap.at);
			if ("refused" in closed) return closed;
			return settled(await write(snap, { extra: q.change(snap.extra) })) ?? { changed: true };
		},
	};
}
