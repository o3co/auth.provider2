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
} from "../statement/statement.ts";
import { paddedFor } from "./padded.ts";

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
	/** Signed, padded and sealed to `r`'s screen; refused where its form, its bucket or the ring refuses. */
	async function sealedFor(
		hash: string,
		r: StatementRecord,
		continued?: Extract<PasskeyManageAsk, { continued: unknown }>["continued"],
	) {
		const rows = (await p.list.listOf(r.subject ?? "")).map(rowOf);
		const payload = {
			v: wireVersion,
			iss: p.issuer,
			t_hash: hash,
			assertion_hash: sha256(r.assertion ?? ""),
			purpose: "passkey-manage",
			keys: rows,
			...(continued
				? {
						continued: {
							stage: continued.stage,
							seq: continued.seq,
							body_hash: continued.bodyHash,
						},
					}
				: {}),
			iat: Math.floor(p.now() / 1000),
			exp: Math.floor(r.exp / 1000),
		};
		if (!payloads.completions.passkeyManage.safeParse(payload).success) return refused("form");
		const prepared = p.keys.prepare("core", typs.completion);
		const signed = await p.keys.sign(prepared, new TextEncoder().encode(canonicalText(payload)));
		if (signed.kind !== "signed") return refused("withdrawn");
		const padded = paddedFor(
			signed.jws,
			rows.map((row) => row.credential_id),
		);
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
			return sealedFor(ask.hash, r, ask.continued);
		}
		// Only the assertion that used it is answered: the bytes as received.
		if (r.assertion !== ask.assertion) return refused("assertion");
		// The one kept is answered before anything that may have lapsed since.
		const kept = keptOn(r);
		if (kept) return kept;
		if (!ask.make) return refused("unknown");
		if (p.now() > r.exp) return refused("expired");
		if (!(await current(p.keys, r.jws))) return refused("unknown");
		const made = await sealedFor(ask.hash, r);
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
