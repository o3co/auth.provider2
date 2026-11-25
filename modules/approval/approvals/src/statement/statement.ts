import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { Keys } from "@mod/keys";
import type { Passkeys } from "@mod/passkeys";
import type { RateLimit, Window } from "@mod/rate-limit";
import { canonicalText, challengeInput, payloads, typs, versions } from "@mod/sdk-core-wire";
import { tokens } from "@mod/transparency-wire";
import { z } from "zod";
import type {
	Approval,
	ApprovalStore,
	Completed,
	CreationRecord,
	IssueAsk,
	Issued,
	ItemsOf,
	KeptChange,
	Purpose,
	SignUp,
	StatementItems,
	StoredStatement,
	Used,
	UsedApproval,
} from "../contract.ts";

/** The wire version this Core writes: the latest `sdk-core-wire` speaks. */
export const wireVersion = versions[versions.length - 1] as (typeof versions)[number];

export const sha256 = (data: string) => createHash("sha256").update(data).digest("base64url");

const id = z.string().min(1);
/** A statement's record: what it was signed as, and how far it went. */
const recordShape = z
	.object({
		purpose: z.enum(["authorization", "passkey-add", "passkey-manage", "creation", "possession"]),
		jws: id,
		sid: id,
		/** Its expiry, in ms. */
		exp: z.number(),
		e_enc: id,
		e_sig: payloads.statement.shape.e_sig,
		state: z.enum(["issued", "used", "completed"]),
		/** A T's: the stages its owner allowed at its issue; its sign-up once begun (F1). */
		continues: z.array(z.literal("sign-up")).min(1).optional(),
		signUp: z.object({ subject: id.optional(), credential: id.optional() }).strict().optional(),
		subject: id.optional(),
		credential: id.optional(),
		/** The id of the asserting key's registration's record on the subject's flow. */
		registration: id.optional(),
		verification: id.optional(),
		/** When it was used, by the kernel's clock, in ms. */
		usedAt: z.number().optional(),
		/** The assertion's JSON text that used it, as received, kept for its approval's record on the flow. */
		assertion: id.optional(),
		/** The last continuation taken: its sequence number and body's hash; as sent, its body (UTF-8 text) and `r‖s`. */
		seq: z.number().int().nonnegative(),
		body: id.optional(),
		sent: z.object({ body: z.string(), signature: id }).strict().optional(),
		/** A sealed continuation's: E_sig's signature, kept with its number; its opened body never is. */
		sig: id.optional(),
		/** A delete's: the longest credential ID's bytes among the subject's keys when its number was taken. */
		pad: z.number().int().nonnegative().optional(),
		/** The call that holds the last continuation's step, and until when (kernel clock, ms). */
		claimed: z.object({ by: id, until: z.number() }).strict().optional(),
		/** What the step of the last continuation answered, once it did. */
		result: z.json().optional(),
		enc: id.optional(),
		/** The digest of the code its completion carries. */
		code: id.optional(),
		/** The path's purpose a possession's key-change completion was asked for. */
		asked: z.enum(["first-key", "passkey-add", "sign-up"]).optional(),
		/** The id of the approval's record on the subject's flow, which the code's chain roots in. */
		record: id.optional(),
		/** That record's reference on the log, its shard and number. */
		ref: z.object({ shard: id, n: z.number().int().positive() }).strict().optional(),
		/** When the log accepted that record, in ms. */
		acceptedAt: z.number().optional(),
		/** Set once its caller let the completion go out: `completionOf` gives none before. */
		published: z.literal(true).optional(),
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
/** The completion a record keeps, where it keeps one whole; none otherwise. */
export const completionIn = (r: StatementRecord): Kept | undefined =>
	r.enc && r.ct && r.record && r.ref && r.acceptedAt !== undefined
		? {
				kind: "completed",
				enc: r.enc,
				ct: r.ct,
				record: r.record,
				ref: r.ref,
				acceptedAt: r.acceptedAt,
			}
		: undefined;
type Kept = Extract<Completed, { kind: "completed" }>;
export const stored = (r: StatementRecord) => r as unknown as StoredStatement;

/** Each purpose's items schema, by the names sdk-core-wire gives them. */
const itemSchemas = {
	authorization: payloads.statement.shape.approval,
	"passkey-add": z.object({}).strict(),
	"passkey-manage": z.object({}).strict(),
	creation: payloads.creation.shape.creation,
	possession: payloads.possession.shape.possession,
} as const;
/** The purposes a key's management approves: no items, used by an assertion. */
const itemless = (purpose: Purpose) => purpose === "passkey-add" || purpose === "passkey-manage";
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
	if (itemless(purpose)) return {};
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

/** The use-once mark of a statement in the flow state, as `authority-rules`' fold names it. */
export const statementMark = (sid: string) => `statement:${sid}`;

/** How long a statement's record outlives the statement, in seconds. */
const keptPastS = 60;
export const recordEnd = (r: StatementRecord) => r.exp + keptPastS * 1000;

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
						// A passkey-add or a passkey-manage carries no member of items.
						...(itemless(ask.purpose) ? {} : { [ask.purpose]: ask.items }),
					};
		const schema = {
			authorization: payloads.statement,
			"passkey-add": payloads.passkeyAdd,
			"passkey-manage": payloads.passkeyManage,
			creation: payloads.creation,
			possession: payloads.possession,
		}[ask.purpose];
		const keys =
			isPoint(ask.screen.eEnc) && tokens.ecThumbprintInput(ask.screen.eSig) !== undefined;
		return schema.safeParse(payload).success && keys ? { payload, common, screen } : undefined;
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
			...(ask.purpose === "authorization" && ask.continues?.length
				? { continues: [...new Set(ask.continues)] }
				: {}),
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
		...(r.registration === undefined ? {} : { registration: r.registration }),
		...(r.verification === undefined ? {} : { verification: r.verification }),
		...(r.usedAt === undefined ? {} : { usedAt: r.usedAt }),
		...(r.state === "completed" ? { completed: true as const } : {}),
		issuedAt: issuedAtOf(r.jws),
		esig: esigOf(r.e_sig),
	});

	/** Marks the record used, from issued alone (a begun sign-up's T by its key); the same evidence again reads as the approval. */
	async function marked(hash: string, use: Partial<StatementRecord>): Promise<Used> {
		const changed = await p.store.change(hash, (current) => {
			const r = recordOf(current) as StatementRecord;
			return r.state === "issued" && signedUpBy(r, use)
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
		if (r.purpose !== "authorization" && !itemless(r.purpose))
			return { kind: "refused", reason: "purpose" };
		const assertion = q.assertion;
		if (r.state !== "issued")
			return r.assertion === assertion
				? { kind: "approved", approval: approvalOf(hash, r) }
				: { kind: "refused", reason: "used" };
		const asked = { challenge: challengeOf(q.statement), allow: [] };
		const response = parsed(assertion);
		if (response === undefined) return { kind: "refused", reason: "malformed" };
		// A begun sign-up's T: refused before the assertion is asked, by the credential it names.
		if (r.signUp && (r.signUp.credential === undefined || r.signUp.credential !== idOf(response)))
			return { kind: "refused", reason: "used" };
		const asserted = await p.passkeys.assert(response, asked);
		if (asserted.kind === "refused") return asserted;
		// approvals' own invariant, whatever passkeys' section says.
		if (!asserted.userVerified) return { kind: "refused", reason: "unverified" };
		if (!signedUpBy(r, asserted)) return { kind: "refused", reason: "used" };
		return marked(hash, {
			subject: asserted.subject,
			credential: asserted.credential,
			registration: asserted.registration,
			assertion,
		});
	}

	async function usedOf(hash: string): Promise<Approval | undefined> {
		const r = recordOf(await p.store.read(hash));
		return r && r.state !== "issued" ? approvalOf(hash, r) : undefined;
	}

	async function rootOf(hash: string) {
		const r = recordOf(await p.store.read(hash));
		const used = r?.purpose === "authorization" && r.state !== "issued";
		return used && r.assertion !== undefined && r.credential !== undefined
			? { statement: r.jws, assertion: r.assertion, credential: r.credential }
			: undefined;
	}

	async function passkeyAddOf(hash: string): Promise<UsedApproval | undefined> {
		const r = recordOf(await p.store.read(hash));
		if (r?.purpose !== "passkey-add" || r.state === "issued" || p.now() > r.exp) return undefined;
		const { subject, credential, registration, assertion } = r;
		if (!subject || !credential || !registration || !assertion) return undefined;
		if (!(await current(p.keys, r.jws))) return undefined;
		const screen = { eEnc: r.e_enc, eSig: r.e_sig };
		const mark = statementMark(r.sid);
		return { statement: r.jws, assertion, subject, credential, registration, screen, mark };
	}

	/** A creation's record as kept, while its statement lives and this generation's ring verifies it; none for any other purpose. */
	async function creationOf(hash: string): Promise<CreationRecord | undefined> {
		const r = recordOf(await p.store.read(hash));
		if (r?.purpose !== "creation" || p.now() > r.exp) return undefined;
		// Signed by the Core's ring of this generation alone, as a use takes a statement.
		if (!(await current(p.keys, r.jws))) return undefined;
		const items = itemsIn(r.jws, "creation") as ItemsOf["creation"];
		return { statement: r.jws, items, screen: { eEnc: r.e_enc, eSig: r.e_sig } };
	}

	async function keptChangeOf(hash: string): Promise<KeptChange | undefined> {
		const r = recordOf(await p.store.read(hash));
		if (r?.purpose !== "possession" || r.state === "issued") return undefined;
		if (!(await current(p.keys, r.jws))) return undefined;
		const named = itemsIn(r.jws, "possession") as ItemsOf["possession"];
		const c = recordOf(await p.store.read(named.creation_hash));
		if (c?.purpose !== "creation" || c.sent === undefined) return undefined;
		// The continuation that made this possession, its body and signature as received.
		if ((c.result as { statement?: unknown } | undefined)?.statement !== r.jws) return undefined;
		const items = itemsIn(c.jws, "creation") as ItemsOf["creation"];
		const creation = { statement: c.jws, items, screen: { eEnc: c.e_enc, eSig: c.e_sig } };
		const continuation = { seq: c.seq, ...c.sent };
		if (items.basis !== "passkey-add" && items.basis !== "sign-up")
			return { creation, continuation };
		const base = recordOf(await p.store.read(items.evidence));
		if (items.basis === "sign-up")
			return base?.purpose === "authorization"
				? { creation, continuation, evidence: base.jws }
				: undefined;
		const { subject, credential, registration, assertion } = base ?? {};
		if (
			base?.purpose !== "passkey-add" ||
			subject !== items.subject ||
			!credential ||
			!registration ||
			!assertion
		)
			return undefined;
		const screen = { eEnc: base.e_enc, eSig: base.e_sig };
		const mark = statementMark(base.sid);
		const used = {
			statement: base.jws,
			assertion,
			subject,
			credential,
			registration,
			screen,
			mark,
		};
		return { creation, continuation, evidence: used };
	}

	async function signUpOf(hash: string): Promise<SignUp | undefined> {
		const r = recordOf(await p.store.read(hash));
		if (r?.purpose !== "authorization" || !r.signUp) return undefined;
		if (!(await current(p.keys, r.jws))) return undefined;
		const { subject, credential } = r.signUp;
		const creation = creationIn(r.result);
		return {
			statement: r.jws,
			...(subject === undefined ? {} : { subject }),
			...(creation === undefined ? {} : { creation }),
			...(credential === undefined ? {} : { credential }),
		};
	}

	async function signUpSubject(hash: string, subject: string): Promise<string | undefined> {
		const changed = await p.store.change(hash, (current) => {
			const r = recordOf(current);
			return r?.purpose === "authorization" && r.signUp && r.signUp.subject === undefined
				? { value: stored({ ...r, signUp: { ...r.signUp, subject } }) }
				: undefined;
		});
		const after = recordOf(changed?.after);
		return after?.purpose === "authorization" ? after.signUp?.subject : undefined;
	}

	async function completionOf(hash: string) {
		const r = recordOf(await p.store.read(hash));
		return r?.purpose === "authorization" && r.state === "completed" && r.published
			? completionIn(r)
			: undefined;
	}

	/** Marks a kept completion as gone out; `published`, or `unknown` where none is kept. */
	async function publish(hash: string): Promise<"published" | "unknown"> {
		const changed = await p.store.change(hash, (current) => {
			const r = recordOf(current);
			return r?.purpose === "authorization" && r.state === "completed" && !r.published
				? { value: stored({ ...r, published: true }) }
				: undefined;
		});
		const after = recordOf(changed?.after);
		return after?.purpose === "authorization" && after.state === "completed" && after.published
			? "published"
			: "unknown";
	}

	return {
		issue,
		use,
		usedOf,
		rootOf,
		passkeyAddOf,
		keptChangeOf,
		creationOf,
		signUpOf,
		signUpSubject,
		completionOf,
		publish,
	};
}

const signedUpBy = (
	r: StatementRecord,
	by: { readonly credential?: string | undefined; readonly subject?: string | undefined },
) =>
	r.signUp === undefined ||
	(r.signUp.credential !== undefined &&
		r.signUp.credential === by.credential &&
		(r.signUp.subject === undefined || r.signUp.subject === by.subject));

const idOf = (response: unknown) => {
	const id = (response as { id?: unknown } | null)?.id;
	return typeof id === "string" ? id : undefined;
};

/** The creation a sign-up's step answered, kept as its result; none for a refusal or no answer. */
export const creationIn = (result: StatementRecord["result"]): string | undefined => {
	const read = z.object({ creation: id }).strict().safeParse(result);
	return read.success ? read.data.creation : undefined;
};

/** The thumbprint of a statement's E_sig: none is a record no statement was issued with, so unavailable. */
const esigOf = (key: unknown): string => {
	const input = tokens.ecThumbprintInput(key);
	if (input === undefined) throw new Unavailable("approvals");
	return sha256(input);
};

/** When a statement was issued, in ms, as its signed `iat` says. */
export const issuedAtOf = (jws: string): number =>
	(
		JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8")) as {
			iat: number;
		}
	).iat * 1000;

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
