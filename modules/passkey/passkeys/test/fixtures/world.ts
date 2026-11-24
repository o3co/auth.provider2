import { createHash, randomBytes } from "node:crypto";
import type { Changes, FlowState } from "@mod/authority-rules";
import { assemble, defineModule, kernelConfig, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { stances } from "@mod/promises";
import {
	type Deciding,
	type FrameStore,
	frameStore,
	type Json,
	operationKinds,
	type PartNext,
	type Placed,
	type Stage,
	type StateOwner,
	stateOwners,
	type TransparencyLog,
	transparency,
	transparencyLog,
} from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import type { AppendAnswer, Flow } from "@mod/transparency-wire";
import { type Credential, ceremonies, freshHandle, type Verification } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import { softwareAuthenticator, testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import {
	type PasskeyStore,
	type PasskeyWitnessing,
	passkeyChanges,
	passkeyPart,
	passkeyStore,
	passkeys,
	passkeyWitnessing,
	registrations,
	type StoredCredential,
} from "../../src/contract.ts";
import passkeysModule from "../../src/module.ts";

const digest = (text: string) => createHash("sha256").update(text).digest("base64url");

/** Frames and part records in memory, held to the versions read, under a store clock a test moves. */
export function memoryFrames(parts: readonly string[]) {
	let now = 0;
	let version = 0;
	const kept = new Map<string, { readonly value: Json; readonly version: number }>();
	const keyOf = (flow: Flow, r?: { part: string; name: string }) =>
		`${flow.of}:${flow.id}/${r ? `${r.part}/${r.name}` : "frame"}`;
	const frames: FrameStore = {
		parts,
		async read(unit, records) {
			const keys = [keyOf(unit.flow), ...records.map((r) => keyOf(unit.flow, r))];
			const entries = keys.map((k) => kept.get(k));
			return {
				unit,
				records,
				frame: entries[0] && structuredClone(entries[0].value),
				held: entries.slice(1).map((e) => e && structuredClone(e.value)),
				now,
				basis: entries.map((e) => e?.version ?? null),
			};
		},
		// passkeys runs on a subject's flow alone: no client's flow record is kept.
		async flowRecord() {
			return undefined;
		},
		async write(read, next, deadline) {
			if (now > deadline) return "late";
			const keys = [keyOf(read.unit.flow), ...read.records.map((r) => keyOf(read.unit.flow, r))];
			const basis = read.basis as readonly (number | null)[];
			if (keys.some((k, i) => (kept.get(k)?.version ?? null) !== basis[i])) return "moved";
			const put = (key: string, value: Json) => {
				version += 1;
				kept.set(key, { value: structuredClone(value), version });
			};
			if (next.frame !== undefined) put(keys[0] as string, next.frame);
			next.records.forEach((r: PartNext, i) => {
				if (r && "value" in r) put(keys[i + 1] as string, r.value);
				if (r && "remove" in r) kept.delete(keys[i + 1] as string);
			});
			return "written";
		},
	};
	return {
		frames,
		at: (t: number) => {
			now = t;
		},
		/** Loses a record of passkeys' part, as a store losing it would. */
		drop: (subject: string, name: string) =>
			kept.delete(keyOf({ of: "subject", id: subject }, { part: passkeyPart, name })),
		value: (subject: string, name?: string, part = passkeyPart) =>
			kept.get(keyOf({ of: "subject", id: subject }, name ? { part, name } : undefined))?.value,
	};
}

/** A log in memory: conditional appends, and the monitor's findings a test gives. */
export function memoryLog(now: () => number): TransparencyLog & {
	judge(flow: Flow, position: number, verdict: "verified" | "held"): void;
	boundary(flow: Flow): void;
} {
	const flows = new Map<string, Placed[]>();
	const onFlow = (flow: Flow) => {
		const key = `${flow.of}:${flow.id}`;
		flows.set(key, flows.get(key) ?? []);
		return flows.get(key) as Placed[];
	};
	let n = 0;
	return {
		writer: { instance: "w1", generation: 1 },
		digest: (preimage) => digest(JSON.stringify(preimage)),
		async append(stage: Stage, prev?: number): Promise<AppendAnswer> {
			const placed = onFlow(stage.flow);
			if (prev !== placed.length) return { v: 1, result: "refused", refusal: "prevMismatch" };
			n += 1;
			const { preimage, ...named } = stage;
			const record = {
				v: 1,
				...named,
				plaintextDigest: digest(JSON.stringify(preimage)),
				sealedTo: [{ key: "m1", ciphertextHash: digest("c") }],
				id: `r${n}`,
				writer: { role: "core", instance: "w1", image: "i1", generation: 1 },
				position: placed.length + 1,
				shard: "s1",
				n,
				acceptedAt: now(),
			} as unknown as Placed["record"];
			placed.push({ record });
			return {
				v: 1,
				result: "accepted",
				id: record.id,
				position: record.position,
				shard: "s1",
				n,
				acceptedAt: record.acceptedAt,
				receipts: ["h.p.s"],
			};
		},
		head: async (flow) => onFlow(flow).length,
		at: async (flow, position) => onFlow(flow)[position - 1],
		of: async (flow, op) => {
			const placed = onFlow(flow).map((p) => p.record);
			return {
				stages: placed.filter((r) => r.op === op).length,
				last: placed.some((r) => r.op === op && r.last),
				abandonments: placed.filter((r) => r.kind === "abandonment" && r.abandons?.op === op)
					.length,
			};
		},
		/** The monitor's erasure boundary, judged verified at once. */
		boundary(flow) {
			const placed = onFlow(flow);
			n += 1;
			const record = {
				v: 1,
				flow,
				kind: "erasureBoundary",
				op: `m${n}`,
				stage: 1,
				last: true,
				id: `r${n}`,
				writer: { role: "monitor", key: "mk" },
				position: placed.length + 1,
				shard: "s1",
				n,
				acceptedAt: now(),
			} as unknown as Placed["record"];
			placed.push({ record, finding: { verdict: "verified", outcome: "took" }, changes: {} });
		},
		judge(flow, position, verdict) {
			const placed = onFlow(flow);
			const p = placed[position - 1] as Placed;
			placed[position - 1] = { ...p, finding: { verdict, outcome: "took" } };
		},
	};
}

/** Owners of the state's fields passkeys does not hold, each in a record of its own part. */
const otherOwner = (name: string, holds: readonly (keyof FlowState)[]): StateOwner => ({
	name,
	holds,
	parts: [name],
	records: () => [{ part: name, name: "state" }],
	read: ([held]) => (held ?? {}) as Partial<FlowState>,
	write: () => [undefined],
});

/** The key change's stage, its content the key its reservation holds. */
export const keyStage = (flow: Flow, op: string, key: { credential: string; publicKey: string }) =>
	({
		kind: "keyChange",
		flow,
		op,
		stage: 1,
		last: true,
		preimage: { v: 1, evidence: [], content: { variant: "first", ...key } },
	}) as Stage;

/** The writer's own record of the kind, after passkeys': the stage it sends, for a resend. */
const preimageRecord = { part: "writer", name: "preimage" } as const;
/**
 * The key change's writer: it registers the kind with its own record, bundle and resend, takes
 * `registrations` and stands on the promises.
 */
export const writer = defineModule(
	{ name: "key-writer", replicaSafe: true, takes: [registrations] },
	(m) => [
		m.contribute(operationKinds).by(() => ({
			...passkeyChanges,
			bundle: false,
			parts: [...passkeyChanges.parts, "writer"],
			records: (flow) => [...passkeyChanges.records(flow), preimageRecord],
			end: (end, held) => [...passkeyChanges.end(end, held), { remove: true }],
			resend: (_flow, op, held) => {
				const stage = held.at(-1) as unknown as Stage | undefined;
				return stage?.op === op ? stage : undefined;
			},
		})),
		m.contribute(stateOwners).by(() => otherOwner("grants", ["approvals", "consumed"])),
		m.contribute(stateOwners).by(() => otherOwner("families", ["families"])),
		m.contribute(stances).by(() => ({
			promise: "front-compromise-new-authorization",
			holds: true,
			by: "key-writer",
		})),
	],
);

/** The writer's part of KE-C01: its changes, and its stage kept beside the reservation where given. */
export const deciding =
	(eff: Changes, stage?: Stage): Deciding =>
	(_state, held) => ({
		digest: "d",
		eff,
		records: held.map((_, i) =>
			i === held.length - 1 && stage ? { value: stage as unknown as Json } : undefined,
		),
	});

/** Credential records in memory, failing on demand as a store that cannot tell. */
export function memoryCredentials() {
	const kept = new Map<string, StoredCredential>();
	let failing = false;
	let failNext = false;
	let before: (() => Promise<void>) | undefined;
	const fails = () => {
		if (failing) throw new Unavailable("store");
	};
	const store: PasskeyStore = {
		async create(id, record) {
			fails();
			if (kept.has(id)) return "exists";
			kept.set(id, structuredClone(record));
			return "created";
		},
		read: async (id) => {
			fails();
			return kept.get(id) && structuredClone(kept.get(id));
		},
		async change(id, change) {
			fails();
			const run = before;
			before = undefined;
			await run?.();
			if (failNext) {
				failNext = false;
				throw new Unavailable("store");
			}
			const record = kept.get(id);
			if (!record) return undefined;
			const next = change(structuredClone(record));
			if (next) kept.set(id, structuredClone(next.value));
			return { before: record, after: kept.get(id) as StoredCredential };
		},
	};
	return {
		store,
		value: (id: string) => kept.get(id) as unknown as Record<string, unknown> | undefined,
		put: (id: string, value: unknown) => kept.set(id, value as StoredCredential),
		fail: (on: boolean) => {
			failing = on;
		},
		/** The next change fails as unavailable, writing nothing. */
		failNextChange: () => {
			failNext = true;
		},
		/** Runs once before the next change reads, as another request would. */
		beforeChange: (run: () => Promise<void>) => {
			before = run;
		},
	};
}

/**
 * A witnessing in memory: one mark per subject, set for a key generation, a mark of a generation
 * before replaced. `hold` makes the next mark
 * wait until the test lets it go on.
 */
export function memoryWitnessing() {
	const marks = new Map<string, number>();
	let held: Promise<void> | undefined;
	const witnessing: PasskeyWitnessing = {
		marked: async (subject) => marks.has(subject),
		mark: async (subject, generation) => {
			const waiting = held;
			held = undefined;
			await waiting;
			// A mark of a generation before is replaced; one of this or a later stays.
			if ((marks.get(subject) ?? -1) < generation) marks.set(subject, generation);
		},
		withdraw: async (subject, generation) => {
			if ((marks.get(subject) ?? generation) < generation) marks.delete(subject);
		},
	};
	return {
		marks,
		witnessing,
		hold: () => {
			let go = () => {};
			held = new Promise<void>((resolve) => {
				go = resolve;
			});
			return go;
		},
		module: defineModule({ name: "witnessing", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(passkeyWitnessing).by(() => witnessing),
		]),
	};
}

/** passkeys composed with transparency, webauthn and a key change's writer, over memory. */
export async function world(
	p: { readonly section?: Record<string, unknown>; readonly modules?: readonly Module[] } = {},
) {
	let clock = 1_000_000;
	const frames = memoryFrames([passkeyPart, "grants", "families", "writer"]);
	const log = memoryLog(() => clock);
	const credentials = memoryCredentials();
	const fakes = defineModule({ name: "fakes", replicaSafe: true, takes: [] }, (m) => [
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => log),
		m.provide(passkeyStore).by(() => credentials.store),
	]);
	const app = await assemble({
		modules: [
			fakes,
			writer,
			transparencyModule,
			webauthnModule,
			passkeysModule,
			...(p.modules ?? []),
		],
		config: { ...kernelConfig(), ...webauthnConfig(), passkeys: p.section ?? {} },
		runtime: quietRuntime({ clock: { now: () => clock } }),
	});
	const keys = await app.get(passkeys);
	const regs = await app.get(registrations);
	const t = await app.get(transparency);
	const cer = await app.get(ceremonies);
	const challenge = () => randomBytes(32).toString("base64url");
	const auth = softwareAuthenticator();
	const client = { origin: testOrigin };
	/** The verification the section asks, as the screen would ask it. */
	const v = p.section?.["user-verification"] as Verification | undefined;
	/** A new credential of `auth`'s, as the ceremony attests it. */
	const created = async (name = "s1", a = auth): Promise<Credential> => {
		const c = challenge();
		const handle = freshHandle(randomBytes);
		const options = cer.creation(c, { handle, name }, [], v);
		const attested = await cer.attest(a.create(options as never, client), c, handle, v);
		if (attested.kind !== "attested") throw new Error(attested.reason);
		return attested.credential;
	};
	/** An assertion over a fresh challenge naming `allow`, none for a discoverable one. */
	const asserting = (allow: readonly Credential[] = [], a = auth, pick?: string) => {
		const c = challenge();
		const options = cer.request(c, allow, v) as never;
		return { challenge: c, response: a.get(options, client, {}, pick) };
	};
	/** A reservation under key generation 0 unless told another. */
	const reserve = (
		q: Omit<Parameters<typeof regs.reserve>[0], "generation"> & { generation?: number },
	) => regs.reserve({ generation: 0, ...q });
	/** A key change sent, judged and taken in by its owner. */
	const land = async (
		subject: string,
		op: string,
		stage: Stage,
		prev: number,
		verdict: "verified" | "held" = "verified",
	) => {
		const flow = { of: "subject", id: subject } as const;
		const sent = await t.send({ flow, op, stage, prev });
		if (!("answer" in sent) || sent.answer.result !== "accepted") throw new Error("not sent");
		log.judge(flow, sent.answer.position, verdict);
		return t.step({ flow, own: op });
	};
	/** A key registered for `subject` from the reservation to the Step; `by` the key that approved it. */
	const register = async (
		subject = "s1",
		first = true,
		a = auth,
		approver?: string,
		generation = 0,
	) => {
		// A key that is not the first is approved by one the subject holds.
		const held = frames.value(subject, "keys") as { keys: Record<string, unknown> } | undefined;
		const by = first ? undefined : (approver ?? Object.keys(held?.keys ?? {})[0]);
		const credential = await created(subject, a);
		const reserved = await reserve({ subject, credential, first, generation });
		if (!("reservation" in reserved)) throw new Error(reserved.refused);
		const shown = asserting([credential], a);
		const verified = await regs.verifyPending({ subject, ...reserved, ...shown });
		if (!("verification" in verified)) throw new Error(verified.refused);
		const key = { credential: credential.id, publicKey: credential.publicKey };
		const stage = keyStage({ of: "subject", id: subject }, reserved.reservation, key);
		const committed = await regs.commit({
			subject,
			...reserved,
			verification: verified.verification,
			decide: deciding({ key: { ...key, ...(by ? { by } : {}) } }, stage),
		});
		if (!("prev" in committed)) throw new Error(committed.refused);
		await land(subject, reserved.reservation, stage, committed.prev);
		return { credential, ...reserved };
	};
	/** The id of the record that made a credential's key, in the subject's flow state. */
	const recordOf = (subject: string, id: string) => {
		const kept = frames.value(subject, "keys") as { keys: Record<string, { credential: string }> };
		return Object.entries(kept.keys).find(([, k]) => k.credential === id)?.[0] as string;
	};
	return {
		app,
		frames,
		log,
		credentials,
		keys,
		regs,
		t,
		auth,
		created,
		asserting,
		reserve,
		land,
		register,
		recordOf,
		advance: (ms: number) => {
			clock += ms;
		},
	};
}
