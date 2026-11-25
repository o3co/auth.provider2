import type { Keys } from "@mod/keys";
import { canonicalText, hpke, payloads, typs } from "@mod/sdk-core-wire";
import type { ApprovalStore, ItemsOf, KeyChangeAsk, KeyChangeCompleted } from "../contract.ts";
import {
	current,
	itemsIn,
	recordOf,
	type StatementRecord,
	stored,
	wireVersion,
} from "../statement/statement.ts";

const refused = (reason: Extract<KeyChangeCompleted, { kind: "refused" }>["reason"]) =>
	({ kind: "refused", reason }) as const;

/** The completion kept on a record for the purpose asked; none where another was asked. */
const keptFor = (
	r: StatementRecord | undefined,
	asked: KeyChangeAsk["purpose"],
): KeyChangeCompleted | undefined =>
	r?.state === "completed" && r.asked === asked && r.enc && r.ct
		? { kind: "completed", enc: r.enc, ct: r.ct }
		: undefined;

/**
 * A key change's completions: the key a used possession names, signed by the Core's ring and sealed to
 * its screen under `completionAad` of the purpose and the possession's hash, then kept on its record.
 * One is made only for a possession unexpired that this generation's ring verifies; once kept, it is
 * given again alike for the same purpose, as authorizations' are.
 */
export function keyChangeCompletionsOver(p: {
	readonly keys: Keys;
	readonly store: ApprovalStore;
	readonly issuer: string;
	readonly now: () => number;
}) {
	return async (ask: KeyChangeAsk): Promise<KeyChangeCompleted> => {
		// The change is the possession's; what the log gave is kept as first asked, so it is no part of the asking.
		const asked = ask.purpose;
		const r = recordOf(await p.store.read(ask.hash));
		if (!r) return refused("unknown");
		if (r.purpose !== "possession") return refused("purpose");
		if (r.state === "completed") return keptFor(r, asked) ?? refused("other");
		if (r.state !== "used") return refused("unused");
		if (p.now() > r.exp) return refused("expired");
		if (!(await current(p.keys, r.jws))) return refused("unknown");
		const named = itemsIn(r.jws, "possession") as ItemsOf["possession"];
		const { purpose, receipt, status, stateOf } = ask;
		// What the log gave, named one by one: nothing else the caller hands is carried.
		const log = {
			...(receipt === undefined ? {} : { receipt }),
			...(status === undefined ? {} : { status }),
			...(stateOf === undefined ? {} : { stateOf }),
		};
		const payload = {
			v: wireVersion,
			iss: p.issuer,
			purpose,
			change: { op: "add", credential_id: named.credential_id, key_jkt: named.key_jkt },
			...log,
			iat: Math.floor(p.now() / 1000),
			exp: Math.floor(r.exp / 1000),
		};
		// Its form is sdk-core-wire's: one it refuses is never signed.
		if (!payloads.completions.keyChange.safeParse(payload).success) return refused("form");
		const prepared = p.keys.prepare("core", typs.completion);
		const signed = await p.keys.sign(prepared, new TextEncoder().encode(canonicalText(payload)));
		if (signed.kind !== "signed") return refused("withdrawn");
		const box = await p.keys.seal(
			new Uint8Array(Buffer.from(r.e_enc, "base64url")),
			hpke.info.completion,
			new TextEncoder().encode(hpke.completionAad(purpose, ask.hash)),
			new TextEncoder().encode(signed.jws),
		);
		const enc = Buffer.from(box.enc).toString("base64url");
		const ct = Buffer.from(box.ct).toString("base64url");
		const saved = await p.store.change(ask.hash, (held) => {
			const now = recordOf(held);
			return now?.state === "used"
				? { value: stored({ ...now, state: "completed", enc, ct, asked }) }
				: undefined;
		});
		// The one kept is answered: another call's, where it kept one first; none where the record is gone.
		const after = recordOf(saved?.after) ?? recordOf(await p.store.read(ask.hash));
		if (!after) return refused("unknown");
		return keptFor(after, asked) ?? refused("other");
	};
}
