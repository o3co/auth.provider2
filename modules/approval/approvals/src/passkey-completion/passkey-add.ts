import type { Keys } from "@mod/keys";
import { canonicalText, hpke, payloads, typs } from "@mod/sdk-core-wire";
import type { ApprovalStore, ItemsOf, PasskeyAddAsk, PasskeyAddCompleted } from "../contract.ts";
import {
	current,
	itemsIn,
	recordOf,
	type StatementRecord,
	sha256,
	stored,
	wireVersion,
} from "../record/record.ts";
import { paddedFor } from "./padded.ts";

const refused = (reason: Extract<PasskeyAddCompleted, { kind: "refused" }>["reason"]) =>
	({ kind: "refused", reason }) as const;

/** The completion kept on a passkey-add's record; none before one is kept. */
const keptOn = (r: StatementRecord): PasskeyAddCompleted | undefined =>
	r.state === "completed" && r.enc && r.ct
		? { kind: "completed", enc: r.enc, ct: r.ct }
		: undefined;

/**
 * A passkey-add's completions: the creation its caller made for it, checked against approvals' own
 * records, signed by the Core's ring and sealed to the passkey-add's screen under `completionAad` of
 * `passkey-add` and its hash, then kept whole in one write. The first kept is the one answered.
 */
export function passkeyAddCompletionsOver(p: {
	readonly keys: Keys;
	readonly store: ApprovalStore;
	readonly issuer: string;
	readonly now: () => number;
}) {
	/** Whether `creation` is one issued here for the passkey-add `r`: by its hash, for its subject, to the same screen. */
	async function madeFor(hash: string, r: StatementRecord, creation: string) {
		const c = recordOf(await p.store.read(sha256(creation)));
		if (c?.purpose !== "creation" || c.jws !== creation) return false;
		const items = itemsIn(c.jws, "creation") as ItemsOf["creation"];
		return (
			items.basis === "passkey-add" &&
			items.evidence === hash &&
			items.subject === r.subject &&
			c.e_enc === r.e_enc &&
			canonicalText(c.e_sig) === canonicalText(r.e_sig)
		);
	}

	return async (ask: PasskeyAddAsk): Promise<PasskeyAddCompleted> => {
		const r = recordOf(await p.store.read(ask.hash));
		if (!r) return refused("unknown");
		if (r.purpose !== "passkey-add") return refused("purpose");
		// Only the assertion that used it is answered: the bytes as received.
		if (r.state !== "issued" && r.assertion !== ask.assertion) return refused("assertion");
		// The one kept is answered before anything that may have lapsed since.
		const kept = keptOn(r);
		if (kept) return kept;
		if (ask.creation === undefined) return refused("unknown");
		if (r.state !== "used") return refused("unused");
		if (p.now() > r.exp) return refused("expired");
		if (!(await current(p.keys, r.jws))) return refused("unknown");
		if (!(await madeFor(ask.hash, r, ask.creation))) return refused("creation");
		const payload = {
			v: wireVersion,
			iss: p.issuer,
			t_hash: ask.hash,
			assertion_hash: sha256(ask.assertion),
			purpose: "passkey-add",
			creation: ask.creation,
			iat: Math.floor(p.now() / 1000),
			exp: Math.floor(r.exp / 1000),
		};
		// Its form is sdk-core-wire's: one it refuses is never signed.
		if (!payloads.completions.passkeyAdd.safeParse(payload).success) return refused("form");
		const prepared = p.keys.prepare("core", typs.completion);
		const signed = await p.keys.sign(prepared, new TextEncoder().encode(canonicalText(payload)));
		if (signed.kind !== "signed") return refused("withdrawn");
		const excluded = (itemsIn(ask.creation, "creation") as ItemsOf["creation"]).options;
		const padded = paddedFor(signed.jws, excluded.exclude_credentials);
		if (padded === undefined) return refused("form");
		const box = await p.keys.seal(
			new Uint8Array(Buffer.from(r.e_enc, "base64url")),
			hpke.info.completion,
			new TextEncoder().encode(hpke.completionAad("passkey-add", ask.hash)),
			new TextEncoder().encode(padded),
		);
		const enc = Buffer.from(box.enc).toString("base64url");
		const ct = Buffer.from(box.ct).toString("base64url");
		const saved = await p.store.change(ask.hash, (held) => {
			const now = recordOf(held);
			return now?.state === "used"
				? { value: stored({ ...now, state: "completed", enc, ct }) }
				: undefined;
		});
		// Another call's, where it kept one first; none where the record is gone.
		const after = recordOf(saved?.after) ?? recordOf(await p.store.read(ask.hash));
		return (after && keptOn(after)) ?? refused("unknown");
	};
}
