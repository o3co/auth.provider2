import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { Keys } from "@mod/keys";
import type { Passkeys } from "@mod/passkeys";
import type { RateLimit, Window } from "@mod/rate-limit";
import { canonicalText, challengeInput, payloads, typs, versions } from "@mod/sdk-core-wire";
import { z } from "zod";
import type {
	Approval,
	ApprovalStore,
	IssueAsk,
	Issued,
	ItemsOf,
	Purpose,
	StatementItems,
	StoredStatement,
	Used,
} from "../contract.ts";

/** The wire version this Core writes: the latest `sdk-core-wire` speaks. */
export const wireVersion = versions[versions.length - 1] as (typeof versions)[number];

export const sha256 = (data: string) => createHash("sha256").update(data).digest("base64url");

const id = z.string().min(1);
/** A statement's record: what it was signed as, and how far it went. */
const recordShape = z
	.object({
		purpose: z.enum(["authorization", "creation", "possession"]),
		jws: id,
		sid: id,
		/** Its expiry, in ms. */
		exp: z.number(),
		e_enc: id,
		e_sig: payloads.statement.shape.e_sig,
		state: z.enum(["issued", "used", "completed"]),
		subject: id.optional(),
		credential: id.optional(),
		verification: id.optional(),
		/** When it was used, by the kernel's clock, in ms. */
		usedAt: z.number().optional(),
		/** The assertion's JSON text that used it, as received, kept for its approval's record on the flow. */
		assertion: id.optional(),
		/** The last continuation taken: its sequence number and body's hash. */
		seq: z.number().int().nonnegative(),
		body: id.optional(),
		/** The call that holds the last continuation's step, and until when (kernel clock, ms). */
		claimed: z.object({ by: id, until: z.number() }).strict().optional(),
		/** What the step of the last continuation answered, once it did. */
		result: z.json().optional(),
		enc: id.optional(),
		/** The digest of the code its completion carries. */
		code: id.optional(),
		ct: id.optional(),
	})
	.strict();
export type StatementRecord = z.output<typeof recordShape>;
/** The record read; a record of another shape is a store that cannot tell, so unavailable. */
export const recordOf = (kept: StoredStatement | undefined): StatementRecord | undefined => {
	if (kept === undefined) return undefined;
	const read = recordShape.safeParse(kept);
	if (!read.success) throw new Unavailable("approvals");
	return read.data;
};
export const stored = (r: StatementRecord) => r as unknown as StoredStatement;

/** Each purpose's items schema, by the names sdk-core-wire gives them. */
const itemSchemas = {
	authorization: payloads.statement.shape.approval,
	creation: payloads.creation.shape.creation,
	possession: payloads.possession.shape.possession,
} as const;
/** The names a purpose's items may carry. */
export const itemNames = (purpose: Purpose): readonly string[] =>
	Object.keys(itemSchemas[purpose].shape);

/** The names each purpose's declared modules fill: refused where the schema lacks one, or two fill it. */
export function declaredOf(items: readonly StatementItems[], refuse: (reason: string) => never) {
	const filled = new Map<string, string>();
	for (const d of items) {
		const known = new Set(itemNames(d.purpose));
		for (const name of d.names) {
			const key = `${d.purpose}/${name}`;
			if (!known.has(name)) refuse(`${d.by} fills ${key}, which no schema names`);
			const other = filled.get(key);
			if (other !== undefined) refuse(`${d.by} and ${other} both fill ${key}`);
			filled.set(key, d.by);
		}
	}
	return (purpose: Purpose) =>
		[...filled.keys()]
			.filter((k) => k.startsWith(`${purpose}/`))
			.map((k) => k.slice(purpose.length + 1));
}

/** The items a statement's payload carries, under its purpose's member. */
export const itemsIn = (jws: string, purpose: Purpose): ItemsOf[Purpose] => {
	const payload = JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));
	return payload[purpose === "authorization" ? "approval" : purpose];
};

export interface StatementParts {
	readonly keys: Pick<Keys, "prepare" | "sign" | "verify">;
	readonly passkeys: Pick<Passkeys, "assert">;
	readonly store: ApprovalStore;
	readonly limit: Pick<RateLimit, "hit">;
	readonly window: Window;
	/** All statements issued, by every replica, in the same window. */
	readonly total: number;
	readonly issuer: string;
	/** The names declared per purpose. */
	readonly declared: (purpose: Purpose) => readonly string[];
	readonly lifetimeS: number;
	readonly maxConcurrent: number;
	readonly now: () => number;
	readonly token: () => string;
}

/** How long a statement's record outlives the statement, in seconds. */
const keptPastS = 60;

/** Issuing statements, and using each once. */
export function statementsOver(p: StatementParts) {
	let signing = 0;

	/** The statement's payload, its common fields fresh; none where the schema or the screen's key refuses it. */
	function payloadOf(ask: IssueAsk) {
		const nowS = Math.floor(p.now() / 1000);
		const common = {
			v: wireVersion,
			iss: p.issuer,
			sid: p.token(),
			iat: nowS,
			exp: nowS + p.lifetimeS,
		};
		const screen = { e_enc: ask.screen.eEnc, e_sig: ask.screen.eSig };
		const payload =
			ask.purpose === "authorization"
				? { ...common, ...screen, purpose: ask.purpose, approval: ask.items }
				: {
						...common,
						...screen,
						nonce: p.token(),
						purpose: ask.purpose,
						[ask.purpose]: ask.items,
					};
		const schema = { authorization: payloads.statement, ...payloads }[ask.purpose];
		return schema.safeParse(payload).success && isPoint(ask.screen.eEnc)
			? { payload, common, screen }
			: undefined;
	}

	async function signed(
		ask: IssueAsk,
		made: NonNullable<ReturnType<typeof payloadOf>>,
	): Promise<Issued> {
		const prepared = p.keys.prepare("core", typs.statement);
		const text = canonicalText(made.payload);
		const answer = await p.keys.sign(prepared, new TextEncoder().encode(text));
		if (answer.kind !== "signed") return { kind: "refused", reason: "withdrawn" };
		const hash = sha256(answer.jws);
		const record: StatementRecord = {
			purpose: ask.purpose,
			jws: answer.jws,
			sid: made.common.sid,
			exp: made.common.exp * 1000,
			...made.screen,
			state: "issued",
			seq: 0,
		};
		// Kept a while past its expiry, so a late use reads as expired.
		await p.store.create(hash, stored(record), (p.lifetimeS + keptPastS) * 1000);
		return {
			kind: "issued",
			statement: answer.jws,
			hash,
			challenge: challengeOf(answer.jws, ask.purpose),
		};
	}

	async function issue(ask: IssueAsk): Promise<Issued> {
		const allowed = new Set(p.declared(ask.purpose));
		if (Object.keys(ask.items).some((name) => !allowed.has(name)))
			return { kind: "refused", reason: "items" };
		const made = payloadOf(ask);
		if (!made) return { kind: "refused", reason: "items" };
		if (signing >= p.maxConcurrent) return { kind: "refused", reason: "busy" };
		signing += 1;
		try {
			const all = await p.limit.hit("approvals.issue-total", "all", {
				...p.window,
				limit: p.total,
			});
			if (all.kind === "limited") return { kind: "refused", reason: "limited" };
			const counted = await p.limit.hit("approvals.issue", ask.by, p.window);
			if (counted.kind === "limited") return { kind: "refused", reason: "limited" };
			return await signed(ask, made);
		} finally {
			signing -= 1;
		}
	}

	const approvalOf = (hash: string, r: StatementRecord): Approval => ({
		hash,
		purpose: r.purpose,
		items: itemsIn(r.jws, r.purpose),
		...(r.subject === undefined ? {} : { subject: r.subject }),
		...(r.credential === undefined ? {} : { credential: r.credential }),
		...(r.verification === undefined ? {} : { verification: r.verification }),
		...(r.usedAt === undefined ? {} : { usedAt: r.usedAt }),
	});

	/** Marks the record used, from issued alone; the same evidence again reads as the approval. */
	async function marked(hash: string, use: Partial<StatementRecord>): Promise<Used> {
		const changed = await p.store.change(hash, (current) => {
			const r = recordOf(current) as StatementRecord;
			return r.state === "issued"
				? { value: stored({ ...r, ...use, usedAt: p.now(), state: "used" }) }
				: undefined;
		});
		const after = recordOf(changed?.after);
		if (!after) return { kind: "refused", reason: "unknown" };
		const same = (Object.keys(use) as (keyof StatementRecord)[]).every((k) => after[k] === use[k]);
		return after.state !== "issued" && same
			? { kind: "approved", approval: approvalOf(hash, after) }
			: { kind: "refused", reason: "used" };
	}

	async function use(
		q: { readonly statement: string } & (
			| { readonly assertion: string }
			| { readonly verification: string }
		),
	): Promise<Used> {
		const hash = sha256(q.statement);
		const r = recordOf(await p.store.read(hash));
		if (r?.jws !== q.statement) return { kind: "refused", reason: "unknown" };
		if (p.now() > r.exp) return { kind: "refused", reason: "expired" };
		// Signed by the Core's ring of this generation alone: a record of an earlier one is not judged by it.
		if (!(await current(p.keys, r.jws))) return { kind: "refused", reason: "unknown" };
		if ("verification" in q) {
			if (r.purpose !== "possession") return { kind: "refused", reason: "purpose" };
			return marked(hash, { verification: q.verification });
		}
		if (r.purpose !== "authorization") return { kind: "refused", reason: "purpose" };
		const assertion = q.assertion;
		if (r.state !== "issued")
			return r.assertion === assertion
				? { kind: "approved", approval: approvalOf(hash, r) }
				: { kind: "refused", reason: "used" };
		const asked = { challenge: challengeOf(q.statement), allow: [] };
		const response = parsed(assertion);
		if (response === undefined) return { kind: "refused", reason: "malformed" };
		const asserted = await p.passkeys.assert(response, asked);
		if (asserted.kind === "refused") return asserted;
		// approvals' own invariant, whatever passkeys' section says.
		if (!asserted.userVerified) return { kind: "refused", reason: "unverified" };
		return marked(hash, {
			subject: asserted.subject,
			credential: asserted.credential,
			assertion,
		});
	}

	async function usedOf(hash: string): Promise<Approval | undefined> {
		const r = recordOf(await p.store.read(hash));
		return r && r.state !== "issued" ? approvalOf(hash, r) : undefined;
	}

	return { issue, use, usedOf };
}

/** The challenge over a statement: sdk-core-wire's input, hashed; a creation's for `create()`, any other's for `get()`. */
export const challengeOf = (jws: string, purpose: Purpose = "authorization") =>
	sha256(challengeInput(jws, purpose === "creation" ? "create" : "get"));

/** Whether the statement verifies by the Core's ring of the generation this Core signs as. */
export const current = async (keys: Pick<Keys, "verify">, jws: string) =>
	(await keys.verify("core", jws, typs.statement)).kind === "valid";

/** Whether a screen's encryption key is a P-256 point, uncompressed: HPKE seals to nothing else. */
const isPoint = (text: string) => {
	const bytes = Buffer.from(text, "base64url");
	return /^[A-Za-z0-9_-]+$/.test(text) && bytes.length === 65 && bytes[0] === 4;
};

const parsed = (text: string): unknown => {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
};
