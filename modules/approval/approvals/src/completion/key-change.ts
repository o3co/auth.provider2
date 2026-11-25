import type { Keys } from "@mod/keys";
import { canonicalText, hpke, payloads, typs } from "@mod/sdk-core-wire";
import type { ApprovalStore, ItemsOf, KeyChangeAsk, KeyChangeCompleted } from "../contract.ts";
import {
	creationIn,
	current,
	itemsIn,
	recordEnd,
	recordOf,
	type StatementRecord,
	sha256,
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
 * A sign-up's key kept on its T (F1): the possession's creation one of basis `sign-up`, the creation
 * its T's sign-up step answered, and the T's `signUp.credential` then kept as the possession's unless
 * another is kept. The T's use waits for it (`statement`). Why not, where it may not.
 */
async function signedUp(
	p: { readonly keys: Keys; readonly store: ApprovalStore },
	possession: ItemsOf["possession"],
): Promise<"creation" | "other" | undefined> {
	const { store } = p;
	const creation = recordOf(await store.read(possession.creation_hash));
	if (creation?.purpose !== "creation" || !(await current(p.keys, creation.jws))) return "creation";
	const made = itemsIn(creation.jws, "creation") as ItemsOf["creation"];
	if (made.basis !== "sign-up") return "creation";
	const held = recordOf(await store.read(made.evidence));
	if (!held || !(await current(p.keys, held.jws))) return "creation";
	const credential = possession.credential_id;
	const kept = (t: StatementRecord | undefined) =>
		t?.purpose === "authorization" &&
		t.signUp !== undefined &&
		creationIn(t.result) !== undefined &&
		sha256(creationIn(t.result) ?? "") === possession.creation_hash;
	const changed = await store.change(made.evidence, (held) => {
		const t = recordOf(held);
		if (!kept(t) || !t?.signUp || t.signUp.credential !== undefined) return undefined;
		return { value: stored({ ...t, signUp: { ...t.signUp, credential } }) };
	});
	const t = recordOf(changed?.after);
	if (!kept(t)) return "creation";
	return t?.signUp?.credential === credential ? undefined : "other";
}

/** The basis of the creation a possession names, where its record is kept. */
const basisOf = async (store: ApprovalStore, possession: ItemsOf["possession"]) => {
	const creation = recordOf(await store.read(possession.creation_hash));
	return creation?.purpose === "creation"
		? (itemsIn(creation.jws, "creation") as ItemsOf["creation"]).basis
		: undefined;
};

/**
 * A key change's completions: the key a used possession names, signed by the Core's ring and sealed to
 * its screen under `completionAad` of the purpose and the possession's hash, then kept on its record.
 * One is made only for a used possession, to its record's end, that this generation's ring verifies; once kept, it is
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
		if (p.now() > recordEnd(r)) return refused("expired");
		if (!(await current(p.keys, r.jws))) return refused("unknown");
		const named = itemsIn(r.jws, "possession") as ItemsOf["possession"];
		// A sign-up's key is kept on its T before its completion: asked again, the same write answers alike.
		if (asked === "sign-up") {
			const why = await signedUp(p, named);
			if (why) return refused(why);
		} else if ((await basisOf(p.store, named)) === "sign-up") return refused("creation");
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
