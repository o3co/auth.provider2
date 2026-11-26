import { type Envelope, emptyState, type FlowState, fold, ruleSchemas } from "@mod/authority-rules";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { type Flow, schemas } from "@mod/transparency-wire";
import type {
	FrameRead,
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
/** The records a tending takes in at most before it yields the flow, and the client's ops one turn tends. */
const tendSteps = 64;

/** A client's flow's record: its open ops, in the order its tending goes round them; its ops closed with nothing on the log. */
type FlowRecord = { readonly open: readonly string[]; readonly closed: readonly string[] };
const ops = (value: Json | undefined): value is readonly string[] =>
	Array.isArray(value) && value.every((op) => typeof op === "string");
/** A client's flow's record as stored; an empty one where it holds none. */
const flowRecordOf = (value: Json | undefined): FlowRecord => {
	if (value === undefined) return { open: [], closed: [] };
	const record = value as { readonly [key: string]: Json };
	if (typeof value !== "object" || value === null || !ops(record.open) || !ops(record.closed))
		throw new TypeError("a stored flow record of another shape");
	return { open: record.open, closed: record.closed };
};
/** How many reads find the intent's kind before contention is unavailable. */
const kindReads = 3;

/** One round of tending each client flow the frame store lists; one unavailable now waits for the next. */
export async function clientTending(
	t: Pick<Transparency, "tend">,
	frames: Pick<FrameStore, "clientFlows">,
): Promise<void> {
	if (!frames.clientFlows) return;
	let cursor: string | undefined;
	do {
		const page: Awaited<ReturnType<NonNullable<FrameStore["clientFlows"]>>> =
			await frames.clientFlows(cursor);
		for (const flow of page.flows) {
			await t.tend(flow).catch((error: unknown) => {
				if (!isUnavailable(error)) throw error;
			});
		}
		cursor = page.cursor;
	} while (cursor !== undefined);
}

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
	const { frames, owners, leaseMs } = p;
	/** The log's axis, its answers held to the wire's forms (the driver's card): else unavailable. */
	const offForm = (): never => {
		throw new Unavailable("transparency");
	};
	const read = <T>(
		schema: { safeParse(v: unknown): { success: boolean; data?: T } },
		v: unknown,
	) => {
		try {
			const parsed = schema.safeParse(v);
			return parsed.success ? (parsed.data as T) : offForm();
		} catch (error) {
			if (isUnavailable(error)) throw error;
			return offForm();
		}
	};
	/** What an adapter's object holds, read once: one whose reading throws is off the form. */
	const fields = <T>(take: () => T): T => {
		try {
			return take();
		} catch {
			return offForm();
		}
	};
	const answered = <A extends { readonly result: string }>(answer: A): A =>
		fields(() => answer.result) === "accepted"
			? (read(schemas.appendAnswer, answer) as unknown as A)
			: answer;
	const log: TransparencyLog = {
		writer: p.log.writer,
		digest: (preimage) => p.log.digest(preimage),
		append: async (stage, prev) => answered(await p.log.append(stage, prev)),
		head: (flow) => p.log.head(flow),
		of: (flow, op) => p.log.of(flow, op),
		reset: async (instruction) => answered(await p.log.reset(instruction)),
		at: async (flow, position) => {
			const placed = await p.log.at(flow, position);
			if (placed === undefined) return undefined;
			// Each member read once, its own or inherited, so a getter's answer is the one checked and kept.
			const held = fields(() => ({
				record: placed.record as unknown,
				finding: placed.finding,
				changes: placed.changes,
			}));
			const record = read(schemas.record, held.record) as Placed["record"];
			const at = record as { readonly flow?: Flow; readonly position?: number };
			if (at.flow?.of !== flow.of || at.flow.id !== flow.id || at.position !== position)
				return offForm();
			return {
				record,
				...(held.finding === undefined ? {} : { finding: held.finding }),
				...(held.changes === undefined ? {} : { changes: held.changes }),
			};
		},
	};
	const kinds = new Map(p.kinds.map((k) => [k.name, k]));
	const bundle = (kind: string) => kinds.get(kind)?.bundle === true;
	/** The unit an event names: a subject's flow, or one op of a client's; none for any other. */
	const unitOf = (flow: Flow, op?: string): IntentUnit | undefined => {
		if (flow.of === "subject") return { flow: { of: "subject", id: flow.id } };
		return flow.of === "client" && op !== undefined
			? { flow: { of: "client", id: flow.id }, op }
			: undefined;
	};
	/** A client's op: its flow is unconditional, holds no state, and its records lie among other ops'. */
	const perOp = (unit: IntentUnit) => "op" in unit;
	const notSubject = { refused: "notSubject" } as const;
	/** A previous position no flow's head ever reaches. */
	const neverAHead = Number.MAX_SAFE_INTEGER;
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
		const holding = perOp(unit) ? [] : owners;
		const owned = holding.map((o) => named(o, o.records(unit.flow)));
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
		const parts = holding.map((o, i) => {
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
			/** On a client's op it ends: nothing of it is on the log. */
			readonly unrecorded?: true;
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
				...(next.frame ? flowNext(snap.read, next.frame, next.unrecorded === true) : {}),
				records: [...owned, ...extra],
			},
			deadline,
		);
	}
	/**
	 * On a client's op, its flow's record follows its frame in the same write: the op is listed while its
	 * intent is open; ended, it leaves the list, its frame is dropped, and it is closed if `unrecorded`.
	 */
	function flowNext(
		read: FrameRead,
		frame: Frame,
		unrecorded: boolean,
	): { readonly drop?: true; readonly flow?: Json } {
		if (!("op" in read.unit)) return {};
		const { op } = read.unit;
		const { open, closed } = flowRecordOf(read.flow);
		if (isOpen(frame.intent))
			return open.includes(op) ? {} : { flow: { open: [...open, op], closed } };
		const ended = unrecorded && !closed.includes(op) ? [...closed, op] : closed;
		return { drop: true, flow: { open: open.filter((o) => o !== op), closed: ended } };
	}
	const settled = (answer: "written" | "moved" | "late") =>
		answer === "written" ? undefined : { refused: answer };
	/** A core write of the frame alone, with the end's records of its kind where it ends an op. */
	async function frameWrite(
		snap: Snapshot,
		kind: OperationKind | undefined,
		w: Written,
		unrecorded = false,
	) {
		const extra = w.end && kind ? kind.end(w.end, snap.extra) : undefined;
		const mark = unrecorded ? { unrecorded: true as const } : {};
		return write(snap, { frame: w.frame, ...(extra ? { extra } : {}), ...mark }, w.ownerUntil);
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

	/** Whether a placed record is a Core record of the op: one of its stages, or an abandonment of it. */
	const ofOp = (placed: Placed, op: string) => {
		const r = placed.record;
		if (r.writer.role !== "core") return false;
		return r.kind === "abandonment" ? r.abandons?.op === op : r.op === op;
	};

	/**
	 * A client's op takes in its own next record, passing over the other records before it unjudged:
	 * nothing is folded, and its frame's applied position is how far along the flow it has looked.
	 */
	async function opStep(unit: IntentUnit & { readonly op: string }, own?: string) {
		const { flow, op } = unit;
		const { snap, kind } = await withKind(unit);
		if (unregistered(snap)) return { refused: "stuck" as const };
		const head = await log.head(flow);
		for (let position = snap.frame.applied + 1; position <= head; position++) {
			const placed = await log.at(flow, position);
			if (!placed || !ofOp(placed, op)) continue;
			if (!placed.finding) return { refused: "unjudged" as const };
			const passed = { ...snap.frame, applied: position - 1 };
			const taken = stepped(passed, snap.at, takenOf(placed), { own: own === op, bundle });
			if ("refused" in taken) return taken;
			const extra = taken.end && kind ? kind.end(taken.end, snap.extra) : undefined;
			const answer = await write(
				snap,
				{ frame: taken.frame, ...(extra ? { extra } : {}) },
				taken.ownerUntil,
			);
			return settled(answer) ?? { position, ...(taken.end ? { end: taken.end } : {}) };
		}
		return { refused: "atHead" as const };
	}

	async function step(unit: IntentUnit, own?: string) {
		if ("op" in unit) return opStep(unit, own);
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
		const unit = unitOf(q.flow, q.op);
		if (!unit) return notSubject;
		const { snap, kind } = await withKind(unit);
		const it = intentOf(snap.frame, snap.at);
		if (!kind || !isOwner(it, snap.at) || it?.op !== q.op || q.stage.op !== q.op) {
			return { refused: "notOwner" as const };
		}
		const unconditional = perOp(unit);
		const answer = await (unconditional ? log.append(q.stage) : log.append(q.stage, q.prev));
		if (answer.result !== "refused") return { answer };
		// Never to be placed: a subject's first stage after another record, a client's after its abandonment.
		// The owner closes the op without a record; on any other refusal the lease's end leaves it.
		const first = q.stage.stage === 1 && q.prev === it.prev && answer.refusal === "prevMismatch";
		if (!(unconditional ? answer.refusal === "abandoned" : first)) return { answer };
		const closed = closedByOwner(snap.frame, snap.at, q.op);
		if ("refused" in closed) return { answer };
		const placed = unconditional ? await log.of(q.flow, q.op) : undefined;
		const unrecorded = placed?.stages === 0 && placed.abandonments === 0;
		if ((await frameWrite(snap, kind, closed, unrecorded)) !== "written") return { answer };
		return { answer, end: closed.end };
	}

	/** Claims an orphan or sends an abandonment; a client's op only once it took in its records to the head (`ready`). */
	async function claim(unit: IntentUnit, ready: boolean) {
		const { flow } = unit;
		const { snap, kind } = await withKind(unit);
		if (unregistered(snap)) return {};
		const it = intentOf(snap.frame, snap.at);
		const unconditional = perOp(unit);
		if (unconditional && !ready) return {};
		// A client's op has no head of its own: taken in to the flow's, it is at its applied position.
		const head = unconditional ? snap.frame.applied : await log.head(flow);
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
		const sent = unconditional ? log.append(stage) : log.append(stage, abandon.prev);
		return { did: "abandonment" as const, answer: await sent };
	}

	/** A unit's tending: taken in to its head (the apply phase of an op it took over), then claimed. */
	async function tendUnit(unit: IntentUnit) {
		// A client's op whose intent is not open has nothing to take in, claim or abandon.
		if (perOp(unit)) {
			const { frame, at } = await frameAt(unit);
			if (!isOpen(intentOf(frame, at))) return { stepped: 0 };
		}
		let count = 0;
		let last: Awaited<ReturnType<typeof step>> | undefined;
		for (; count < tendSteps; count++) {
			const first = await frameAt(unit);
			const it = intentOf(first.frame, first.at);
			// A replica's tending is the apply phase of an op it took over.
			const own = it?.taken && isOwner(it, first.at) ? it.op : undefined;
			last = await step(unit, own);
			if (!("position" in last)) break;
		}
		const ready = last !== undefined && "refused" in last && last.refused === "atHead";
		return { stepped: count, ...(await claim(unit, ready)) };
	}

	/**
	 * The ops one turn on a client's flow tends: the first its record lists, moved to the list's back in
	 * one write, so the next turn goes on past them and every listed op is reached in its turn.
	 */
	async function turnOf(flow: {
		readonly of: "client";
		readonly id: string;
	}): Promise<readonly string[]> {
		let { open } = flowRecordOf(await frames.flowRecord(flow));
		for (let read = 0; read < kindReads && open.length > tendSteps; read++) {
			const at = await frames.read({ flow, op: open[0] as string }, []);
			const record = flowRecordOf(at.flow);
			open = record.open;
			const turn = open.slice(0, tendSteps);
			const next = { ...record, open: [...open.slice(tendSteps), ...turn] };
			const answer = await frames.write(at, { flow: next, records: [] }, at.now + writeWindowMs);
			if (answer === "written") return turn;
		}
		return open.slice(0, tendSteps);
	}

	return {
		async decide(q) {
			const kind = kinds.get(q.kind);
			if (!kind) throw new TypeError(`no kind of operation ${q.kind} is registered`);
			const unit = unitOf(q.flow, q.op);
			if (!unit) return notSubject;
			const snap = await snapshot(unit, named(kind, kind.records(q.flow)));
			const head = await log.head(q.flow);
			const placed = await log.of(q.flow, q.op);
			// A client's op is decided once, whatever its end: its frame, its stages or abandonments on the
			// log, or its flow's record where it ended with none, show it; it looks on from the head.
			const ended =
				snap.frame.intent !== null ||
				placed.stages > 0 ||
				placed.abandonments > 0 ||
				flowRecordOf(snap.read.flow).closed.includes(q.op);
			if (perOp(unit) && ended) return { refused: "ended" as const };
			const frame = perOp(unit) ? { ...snap.frame, applied: head } : snap.frame;
			const guard = decided(frame, snap.at, {
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
			const next = decided(frame, snap.at, {
				...asked,
				op: q.op,
				kind: q.kind,
				head,
				placed,
				leaseMs,
			});
			if ("refused" in next) return next;
			const answer = await write(snap, { frame: next.frame, extra: asked.records });
			return settled(answer) ?? { prev: frame.applied };
		},
		send,
		async rebase(q) {
			const unit = unitOf(q.flow, q.op);
			if (!unit) return notSubject;
			const { snap, kind } = await withKind(unit);
			if (!kind) return { refused: "notOwner" as const };
			// A client's op has no previous position to move: its appends name none.
			const head = perOp(unit) ? snap.frame.applied : await log.head(q.flow);
			const moved = rebased(snap.frame, snap.at, q.op, head);
			if ("refused" in moved) return moved;
			// The first stage is never put again (A16): its refusal closes the op in `send`.
			if ((await log.of(q.flow, q.op)).stages === 0) return { refused: "unplaced" as const };
			if (q.recheck(snap.state) && perOp(unit)) return { prev: head };
			if (q.recheck(snap.state))
				return settled(await frameWrite(snap, kind, moved)) ?? { prev: head };
			const closed = closedByOwner(snap.frame, snap.at, q.op);
			if ("refused" in closed) return closed;
			const answer = await frameWrite(snap, kind, closed);
			return answer === "written" ? { end: closed.end } : { refused: answer };
		},
		async step(q) {
			// A client's flow is stepped by its op, which its owner names.
			const unit = unitOf(q.flow, q.own);
			return unit ? step(unit, q.own) : notSubject;
		},
		async tend(flow) {
			const unit = unitOf(flow);
			if (unit) return tendUnit(unit);
			if (flow.of !== "client") return notSubject;
			// A client's flow: the open ops its record lists first, as many as one turn takes.
			const client = { of: "client", id: flow.id } as const;
			let stepped = 0;
			let did = {};
			// An op that meets a record off the form keeps no later op of the turn from its own.
			let failed: unknown;
			for (const op of await turnOf(client)) {
				try {
					const { stepped: count, ...claimed } = await tendUnit({ flow: client, op });
					stepped += count;
					if ("did" in claimed) did = claimed;
				} catch (error) {
					if (!isUnavailable(error)) throw error;
					failed ??= error;
				}
			}
			if (failed !== undefined) throw failed;
			return { stepped, ...did };
		},
		async reset(q) {
			return { answer: await log.reset(q.instruction) };
		},
		async receiptOf(q) {
			// A subject's flow alone: an unconditional append names no previous position to hold it back.
			if (q.flow.of !== "subject") return notSubject;
			const { stage } = q;
			if (stage.op !== q.op || stage.flow.of !== q.flow.of || stage.flow.id !== q.flow.id)
				throw new TypeError("a stage asked again names another op or flow");
			// Read first, writing nothing: an op of no stage on the log is not asked of it at all.
			if ((await log.of(q.flow, q.op)).stages === 0) return { refused: "unplaced" as const };
			// After a position no head reaches: the log answers the same id as first placed before it
			// reads the position, and refuses any stage it does not hold, so this never places one.
			const answer = await log.append(stage, neverAHead);
			if (answer.result === "refused" && answer.refusal === "prevMismatch")
				return { refused: "unplaced" as const };
			return { answer };
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
