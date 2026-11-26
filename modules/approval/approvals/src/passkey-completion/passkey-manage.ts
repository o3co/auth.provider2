import { continuations } from "@mod/continuation-wire";
import type { Keys } from "@mod/keys";
import type { KeyList, KeyRow } from "@mod/passkeys";
import { canonicalText, hpke, payloads, typs } from "@mod/sdk-core-wire";
import type { ApprovalStore, PasskeyManageAsk, PasskeyManageCompleted } from "../contract.ts";
import {
	current,
	recordEnd,
	recordOf,
	type StatementRecord,
	sha256,
	stored,
	wireVersion,
} from "../record/record.ts";
import { longestOf } from "./padded.ts";

const refused = (reason: Extract<PasskeyManageCompleted, { kind: "refused" }>["reason"]) =>
	({ kind: "refused", reason }) as const;

/** The list's completion kept on a passkey-manage's record; none before one is kept. */
const keptOn = (r: StatementRecord): PasskeyManageCompleted | undefined =>
	r.state === "completed" && r.enc && r.ct
		? { kind: "completed", enc: r.enc, ct: r.ct }
		: undefined;

/** A key's row as the list shows it: its label, or `Passkey` and the day it was reserved (UTC); seconds. */
const rowOf = (k: KeyRow) => ({
	credential_id: k.credential,
	label:
		k.label ??
		(k.createdAt === undefined
			? "Passkey"
			: `Passkey ${new Date(k.createdAt).toISOString().slice(0, 10)}`),
	created_at: k.createdAt === undefined ? 0 : Math.floor(k.createdAt / 1000),
});

/**
 * A passkey-manage's completions: its subject's keys as passkeys lists them, signed, padded and sealed
 * to its screen; the approval's kept whole in one write, a continuation's (`continued`) its step's.
 */
export function passkeyManageCompletionsOver(p: {
	readonly keys: Keys;
	readonly store: ApprovalStore;
	readonly list: Pick<KeyList, "listOf">;
	readonly issuer: string;
	readonly now: () => number;
}) {
	type Continued = Extract<PasskeyManageAsk, { continued: unknown }>["continued"];

	/** Signed, padded to the bucket `ids`' longest chooses and sealed to `r`'s screen; refused where its form, bucket or ring refuses. */
	async function sealed(hash: string, r: StatementRecord, payload: object, longest: number) {
		const prepared = p.keys.prepare("core", typs.completion);
		const signed = await p.keys.sign(prepared, new TextEncoder().encode(canonicalText(payload)));
		if (signed.kind !== "signed") return refused("withdrawn");
		const padded = hpke.paddedCompletion(signed.jws, longest);
		if (padded === undefined) return refused("form");
		const box = await p.keys.seal(
			new Uint8Array(Buffer.from(r.e_enc, "base64url")),
			hpke.info.completion,
			new TextEncoder().encode(hpke.completionAad("passkey-manage", hash)),
			new TextEncoder().encode(padded),
		);
		const enc = Buffer.from(box.enc).toString("base64url");
		return { kind: "completed", enc, ct: Buffer.from(box.ct).toString("base64url") } as const;
	}

	/** The subject's keys as passkeys lists them now; a continuation's, the one it answers named. */
	async function listed(hash: string, r: StatementRecord, continued?: Continued) {
		const rows = (await p.list.listOf(r.subject ?? "")).map(rowOf);
		const named = continued && {
			stage: continued.stage,
			seq: continued.seq,
			body_hash: continued.bodyHash,
			...("refused" in continued ? { refused: continued.refused } : {}),
		};
		const payload = {
			v: wireVersion,
			iss: p.issuer,
			t_hash: hash,
			assertion_hash: sha256(r.assertion ?? ""),
			purpose: "passkey-manage",
			keys: rows,
			...(named ? { continued: named } : {}),
			iat: Math.floor(p.now() / 1000),
			exp: Math.floor(r.exp / 1000),
		};
		if (!payloads.completions.passkeyManage.safeParse(payload).success) return refused("form");
		return sealed(
			hash,
			r,
			payload,
			Math.max(r.pad ?? 0, longestOf(rows.map((row) => row.credential_id))),
		);
	}

	/** A delete taken: its key change with the log's receipt, padded by the keys left and the one taken. */
	async function deleted(hash: string, r: StatementRecord, credential: string, receipt: string) {
		const payload = {
			v: wireVersion,
			iss: p.issuer,
			purpose: "passkey-manage",
			change: { op: "delete", credential_id: credential },
			receipt,
			iat: Math.floor(p.now() / 1000),
			exp: Math.floor(r.exp / 1000),
		};
		if (!payloads.completions.keyChange.safeParse(payload).success) return refused("form");
		const left = (await p.list.listOf(r.subject ?? "")).map((k) => k.credential);
		return sealed(hash, r, payload, Math.max(r.pad ?? 0, longestOf([...left, credential])));
	}

	return async (ask: PasskeyManageAsk): Promise<PasskeyManageCompleted> => {
		const r = recordOf(await p.store.read(ask.hash));
		if (!r) return refused("unknown");
		if (r.purpose !== "passkey-manage") return refused("purpose");
		if (r.state === "issued" || !r.subject || !r.assertion) return refused("unused");
		if ("continued" in ask) {
			// Only the continuation its record took and holds unanswered: its number and body as taken.
			const c = ask.continued;
			const held = r.claimed !== undefined && r.claimed.until >= p.now();
			if (r.seq !== c.seq || r.body !== c.bodyHash || r.result !== undefined || !held)
				return refused("continued");
			// A continuation's step, taken before the statement expired, may end up to its record's end.
			if (p.now() > recordEnd(r)) return refused("expired");
			if (!(await current(p.keys, r.jws))) return refused("unknown");
			if (c.stage === "delete" && "credential" in c) {
				// The key it names is its body's: the body's hash, as the record took it.
				const body = continuations.bodyText("delete", { credential_id: c.credential });
				if (body === undefined || sha256(body) !== c.bodyHash) return refused("continued");
				return deleted(ask.hash, r, c.credential, c.receipt);
			}
			return listed(ask.hash, r, c);
		}
		// Only the assertion that used it is answered: the bytes as received.
		if (r.assertion !== ask.assertion) return refused("assertion");
		// The one kept is answered before anything that may have lapsed since.
		const kept = keptOn(r);
		if (kept) return kept;
		if (!ask.make) return refused("unknown");
		if (p.now() > r.exp) return refused("expired");
		if (!(await current(p.keys, r.jws))) return refused("unknown");
		const made = await listed(ask.hash, r);
		if (made.kind !== "completed") return made;
		// Kept only from used, and only unexpired, read in that write.
		const saved = await p.store.change(ask.hash, (held) => {
			const now = recordOf(held);
			return now?.state === "used" && p.now() <= now.exp
				? { value: stored({ ...now, state: "completed", enc: made.enc, ct: made.ct }) }
				: undefined;
		});
		const after = recordOf(saved?.after) ?? recordOf(await p.store.read(ask.hash));
		return (after && keptOn(after)) ?? refused(p.now() > r.exp ? "expired" : "unknown");
	};
}
