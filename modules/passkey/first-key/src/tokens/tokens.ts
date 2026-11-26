import { createHash, timingSafeEqual } from "node:crypto";
import type { BuildContext } from "@mod/kernel";
import type { SigningKey } from "@mod/sdk-core-wire";
import type { Kept, StoredToken } from "../contract.ts";
import { firstKeyTokens } from "../contract.ts";
import type { Settings } from "../section.ts";
import { mailTokenBytes } from "../sizes.ts";

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const tokenKey = (token: string) => `token:${sha256(token)}`;
const answerKey = (nonce: string) => `answer:${nonce}`;
/** A code bound to its token: the code alone, eight digits, is never kept. */
const codeHash = (token: string, code: string) => sha256(`${token}\u0000${code}`);
const same = (a: string, b: string) =>
	a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** The request that tried a token: its mail nonce and its sealed bytes' digest. */
export interface Request {
	readonly nonce: string;
	readonly digest: string;
}

/** A mail token as kept: its subject and code, the requests counted against it, and how far it went. */
interface TokenRecord {
	readonly subject: string;
	readonly code: string;
	/** When it ends, kernel clock ms, fixed as it is issued: past it no try and no use holds, whatever the store keeps. */
	readonly until: number;
	/** When its evidence began, the start's time, kernel clock ms: a revocation since refuses its creation. */
	readonly since: number;
	readonly tried: readonly Request[];
	readonly state: "issued" | "claimed" | "used" | "revoked";
	/** The request it is claimed or used by, fixed once claimed. */
	readonly by?: Request;
}

/** The answer a mail's side was given, as kept by its nonce: the request's digest and E_sig, the statement, its token's record key. */
interface Answer {
	readonly digest: string;
	readonly eSig: SigningKey;
	readonly statement: string;
	readonly tokenKey: string;
}

/** What a recovery is checked against: the request's digest and the E_sig it was answered for. */
export interface Recoverable {
	readonly digest: string;
	readonly eSig: SigningKey;
}

/** A token issued: its text, for the mail alone, and when it ends. */
export interface IssuedToken {
	readonly token: string;
	readonly until: number;
}

/**
 * A token tried: claimed by this request (afresh, or again after a fall), with its own subject and
 * when its evidence began, as its record holds them; used by it; or refused.
 */
export type Tried =
	| { readonly kind: "claimed"; readonly subject: string; readonly since: number }
	| { readonly kind: "used" }
	| { readonly kind: "refused" };
const refused: Tried = { kind: "refused" };

const asRecord = (kept: StoredToken | undefined) => kept as unknown as TokenRecord | undefined;
const asAnswer = (kept: StoredToken | undefined) => kept as unknown as Answer | undefined;
const stored = (value: TokenRecord | Answer) => value as unknown as StoredToken;
const isBy = (r: TokenRecord | undefined, q: Request) =>
	r?.by?.nonce === q.nonce && r.by.digest === q.digest;
const counted = (r: TokenRecord, q: Request) =>
	r.tried.some((t) => t.nonce === q.nonce && t.digest === q.digest);

/** A random code of eight decimal digits, every one alike likely. */
export function codeOf(random: (bytes: number) => Uint8Array): string {
	for (;;) {
		const n = Buffer.from(random(4)).readUInt32BE(0);
		// Past the last whole hundred million, drawn again, so no digit leans.
		if (n < 4_200_000_000) return String(n % 100_000_000).padStart(8, "0");
	}
}

/**
 * A first key's mail tokens and its mail's side's answers: each try decided in one write of its token's
 * record, a request counted once and a claim fixed to it; an answer given only while its token is used by it.
 */
export function tokensOver(p: {
	readonly store: Kept<StoredToken>;
	readonly random: (bytes: number) => Uint8Array;
	readonly now: () => number;
	readonly lifetimeMs: number;
	readonly tries: number;
}) {
	/** Marks the token used by the request that claimed it, before its end; whether it is so, used by it already or now. */
	const use = async (key: string, q: Request): Promise<boolean> => {
		const changed = await p.store.change(key, (current) => {
			const r = asRecord(current) as TokenRecord;
			return p.now() <= r.until && r.state === "claimed" && isBy(r, q)
				? { value: stored({ ...r, state: "used" }) }
				: undefined;
		});
		const after = asRecord(changed?.after);
		return (
			after !== undefined && p.now() <= after.until && after.state === "used" && isBy(after, q)
		);
	};
	return {
		/**
		 * A new token for the subject, its code given, its evidence begun at `since`: the token's text,
		 * for the mail alone, and its end.
		 */
		issue: async (subject: string, code: string, since: number): Promise<IssuedToken> => {
			const until = p.now() + p.lifetimeMs;
			for (;;) {
				const token = Buffer.from(p.random(mailTokenBytes)).toString("base64url");
				const record: TokenRecord = {
					subject,
					code: codeHash(token, code),
					until,
					since,
					tried: [],
					state: "issued",
				};
				if ((await p.store.create(tokenKey(token), stored(record), p.lifetimeMs)) === "created")
					return { token, until };
			}
		},
		/**
		 * Tries the token for a request, the subject its identifier names (or none) and its code, in one
		 * write: an issued one matching is claimed by it; one not matching counts the request once,
		 * revoked at the tries; a request counted before is refused uncounted.
		 */
		attempt: async (
			token: string,
			q: Request,
			subject: string | undefined,
			code: string,
		): Promise<Tried> => {
			const changed = await p.store.change(tokenKey(token), (current) => {
				const r = asRecord(current) as TokenRecord;
				if (p.now() > r.until || counted(r, q) || r.state !== "issued") return undefined;
				if (subject === r.subject && same(codeHash(token, code), r.code))
					return { value: stored({ ...r, state: "claimed", by: q }) };
				const tried = [...r.tried, q];
				return {
					value: stored({ ...r, tried, state: tried.length >= p.tries ? "revoked" : "issued" }),
				};
			});
			const after = asRecord(changed?.after);
			if (!after || p.now() > after.until || counted(after, q) || !isBy(after, q)) return refused;
			if (after.state === "used") return { kind: "used" };
			return after.state === "claimed"
				? { kind: "claimed", subject: after.subject, since: after.since }
				: refused;
		},
		/** What a recovery of the nonce is checked against, its statement never; none where no answer is kept. */
		recoverable: async (nonce: string): Promise<Recoverable | undefined> => {
			const answer = asAnswer(await p.store.read(answerKey(nonce)));
			return answer && { digest: answer.digest, eSig: answer.eSig };
		},
		/**
		 * The answer kept for the request's nonce, given only while its token is used by that request,
		 * the token marked used where it was claimed by it: none for any other request, or once the
		 * token ended (§7.7).
		 */
		answered: async (q: Request): Promise<string | undefined> => {
			const answer = asAnswer(await p.store.read(answerKey(q.nonce)));
			if (answer?.digest !== q.digest) return undefined;
			return (await use(answer.tokenKey, q)) ? answer.statement : undefined;
		},
		/**
		 * Keeps the statement as the answer to the request, for the token it claimed and E_sig, unless one
		 * is kept for its nonce; living until its token's end and a minute.
		 */
		keep: async (
			q: Request,
			token: string,
			given: { readonly eSig: SigningKey; readonly statement: string },
		): Promise<void> => {
			const r = asRecord(await p.store.read(tokenKey(token)));
			// Measured just before the write: a late write only moves the end on, never back.
			const lifetimeMs = (r?.until ?? p.now()) - p.now() + 60_000;
			const answer: Answer = { digest: q.digest, ...given, tokenKey: tokenKey(token) };
			await p.store.create(answerKey(q.nonce), stored(answer), Math.max(lifetimeMs, 1));
		},
	};
}

export type Tokens = ReturnType<typeof tokensOver>;

export const tokensTakes = [firstKeyTokens] as const;

export async function tokensOf(c: BuildContext<Settings>) {
	return tokensOver({
		store: await c.get(firstKeyTokens),
		random: (n) => c.random.bytes(n),
		now: c.clock.now,
		lifetimeMs: c.section["token-lifetime"] * 1000,
		tries: c.section["code-tries"],
	});
}
