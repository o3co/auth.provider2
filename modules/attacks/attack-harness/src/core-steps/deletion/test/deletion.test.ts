import type { Written } from "@mod/authority-rules/testing";
import { continuations } from "@mod/continuation-wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Flow, type InProcess, inProcess } from "../../../in-process/test/in-process.ts";
import { readyWithinMs } from "../../../pattern/test/launch.ts";
import { honestRelay } from "../../../relay/relay.ts";
import { browser } from "../../../roles/test/browser.ts";
import type { RelyingParty } from "../../../roles/test/rp.ts";
import { stopped } from "../../../roles/test/screen.ts";
import { type Person, screenOrigin } from "../../../world/test/world.ts";
import {
	flowOf,
	heldAdd,
	heldDelete,
	heldLogin,
	heldPair,
	loginProbe,
	records,
	refusalOf,
	sha256,
	thiefSignature,
	tokenDigest,
} from "../../test/kit.ts";
import { expectSwept, ledgerOf } from "../../test/sweep.ts";

// The deletion group, K-1 to K-6: a bad writer places a key's deletion its evidence
// does not hold (M), and beside it the same with the attack's one point undone (U).

let core: InProcess;
let rp: RelyingParty;
beforeAll(async () => {
	core = await inProcess({ clientIds: ["rp-del"] }, honestRelay);
	rp = core.world.rps[0] as RelyingParty;
}, readyWithinMs + 10_000);
afterAll(() => core?.stop());

const honestly = { verdict: "unsupported", outcome: "took" };
const forged = { verdict: "forged", outcome: "didNotTake" };

/** Places a record as the bad writer, kept in the Core's ledger: its id, and the log's judgment of it. */
const place = (flow: Flow, record: Written) => ledgerOf(core).placed(flow, record);
/** Places a record as the bad writer, and the log's judgment of it. */
const placed = async (flow: Flow, record: Written) => (await place(flow, record)).judged;

/** A bundle's tokens: an access token, and a refresh family where it makes one. */
const tokensOf = (seed: string, family: boolean) => [
	{ frame: "accessToken" as const, digest: tokenDigest(`${seed}-at`) },
	...(family ? [{ frame: "family" as const, digest: tokenDigest(`${seed}-family`) }] : []),
];

/** A person with keys of their own beyond the first, each on another authenticator. */
async function personWith(more: number): Promise<{ who: Person; keys: string[] }> {
	const who = await core.world.person();
	const keys = [who.credential];
	for (let i = 0; i < more; i++) {
		const added = await who.screen.addKey(
			await core.world.front(),
			who.credential,
			browser(screenOrigin),
		);
		if (stopped(added)) throw new Error(`add: ${JSON.stringify(added)}`);
		keys.push(added.credential);
	}
	return { who, keys };
}

/**
 * The Core's side after the bad writer's records: a new login stalls (the flow's records no intent
 * holds are taken in by none), and every key the subject held is still live, held as before.
 */
async function untaken(who: Person, flow: Flow, keys: readonly string[]) {
	expect(refusalOf(await loginProbe(core, who, rp))).toBe("temporarily_unavailable");
	for (const key of keys)
		expect(await core.keysRead.keyOf(key)).toMatchObject({ subject: flow.id });
	expect([...(await core.keysRead.heldBy(flow.id)).credentials].sort()).toEqual([...keys].sort());
}

describe("a key's deletion the evidence does not hold", () => {
	it("K-1: one whose continuation another key signed is forged, the screen's own taking (DEL_reg_noApproval)", async () => {
		const { who, keys } = await personWith(1);
		const [approver, target] = keys as [string, string];
		const { flow } = await flowOf(core, approver);
		const evidence = await heldDelete(core, who, approver, target);
		const input = continuations.of(
			"delete",
			sha256(evidence.input.statement),
			1,
			sha256(evidence.input.body),
		);
		const thief = { ...evidence.continuation, signature: thiefSignature(input) };
		expect(
			await placed(flow, records.deletedKey(flow, "k1-m", evidence.by, thief, target)),
		).toEqual(forged);
		expect(
			await placed(
				flow,
				records.deletedKey(flow, "k1-u", evidence.by, evidence.continuation, target),
			),
		).toEqual(honestly);
		await untaken(who, flow, keys);
	});

	it("K-4: one deleting a key its continuation does not name is forged, the one it names taking (DEL_reg_noTarget)", async () => {
		const { who, keys } = await personWith(2);
		const [approver, named, other] = keys as [string, string, string];
		const { flow } = await flowOf(core, approver);
		const evidence = await heldDelete(core, who, approver, named);
		expect(
			await placed(
				flow,
				records.deletedKey(flow, "k4-m", evidence.by, evidence.continuation, other),
			),
		).toEqual(forged);
		expect(
			await placed(
				flow,
				records.deletedKey(flow, "k4-u", evidence.by, evidence.continuation, named),
			),
		).toEqual(honestly);
		await untaken(who, flow, keys);
	});

	it("K-2: one approved by another subject's key, naming the victim's, is forged, the victim's own taking (DEL_reg_anySubject)", async () => {
		const victim = await personWith(1);
		const attacker = await personWith(0);
		const [own, target] = victim.keys as [string, string];
		const [thief] = attacker.keys as [string];
		const { flow } = await flowOf(core, own);
		// The attacker's own statement, assertion and continuation, the continuation naming the victim's key.
		const theirs = await heldDelete(core, attacker.who, thief, target);
		const victims = await heldDelete(core, victim.who, own, target);
		expect(
			await placed(flow, records.deletedKey(flow, "k2-m", theirs.by, theirs.continuation, target)),
		).toEqual(forged);
		expect(
			await placed(
				flow,
				records.deletedKey(flow, "k2-u", victims.by, victims.continuation, target),
			),
		).toEqual(honestly);
		await untaken(victim.who, flow, victim.keys);
	});

	it("K-3: one carrying a rename's continuation is forged, a delete's taking (DEL_reg_noStage)", async () => {
		// The screen's rename, end to end, takes: the stage held back below is an honest one.
		const named = await personWith(0);
		const renamed = await named.who.screen.renameKey(
			await core.world.front(),
			named.who.credential,
			named.who.credential,
			"laptop",
		);
		expect(renamed).toEqual({ applied: true });
		const { who, keys } = await personWith(1);
		const [approver, target] = keys as [string, string];
		const { flow } = await flowOf(core, approver);
		// One approval's two continuations: M carries its rename, U its delete; nothing else differs.
		const pair = await heldPair(core, who, approver, target, "phone");
		expect(
			await placed(flow, records.deletedKey(flow, "k3-m", pair.by, pair.rename, target)),
		).toEqual(forged);
		expect(
			await placed(flow, records.deletedKey(flow, "k3-u", pair.by, pair.remove, target)),
		).toEqual(honestly);
		await untaken(who, flow, keys);
	});

	it("K-5: one deleting the last key is forged, the same deletion taking once a key is added (DEL_reg_noLast)", async () => {
		const { who, keys } = await personWith(0);
		const [only] = keys as [string];
		const { flow } = await flowOf(core, only);
		const remove = await heldDelete(core, who, only, only);
		const add = await heldAdd(core, who, only);
		const waiting = (await core.keysRead.heldBy(flow.id)).pending;
		expect(
			await placed(flow, records.deletedKey(flow, "k5-m", remove.by, remove.continuation, only)),
		).toEqual(forged);
		expect(
			await placed(flow, records.addedKey(flow, add.reservation, add.by, add.ceremony)),
		).toEqual(honestly);
		// The same deletion's preimage under another op: the flow holds two keys now.
		expect(
			await placed(flow, records.deletedKey(flow, "k5-u", remove.by, remove.continuation, only)),
		).toEqual(honestly);
		await untaken(who, flow, keys);
		// The key added was never taken in: it waits on its reservation as it did, live for none.
		expect(await core.keysRead.keyOf(add.ceremony.credential)).toBeUndefined();
		expect(waiting).toMatchObject({
			reservation: add.reservation,
			credential: add.ceremony.credential,
			publicKey: add.ceremony.publicKey,
		});
		expect((await core.keysRead.heldBy(flow.id)).pending).toEqual(waiting);
	});

	it("K-6a: a code's bundle making a family once its approving key is deleted is forged, one made before taking (DEL_reg_noRootLive)", async () => {
		const { who, keys } = await personWith(1);
		const [first] = keys as [string, string];
		const { flow } = await flowOf(core, first);
		const one = await heldLogin(core, who, rp, first);
		const two = await heldLogin(core, who, rp, first);
		const remove = await heldDelete(core, who, first, first);
		const code = (n: string) =>
			({ via: "code", code: sha256(`k6a-code-${n}`), client: rp.clientId }) as const;
		const a1 = await place(flow, records.approval(flow, one.op, one.by, code("1").code));
		const a2 = await place(flow, records.approval(flow, two.op, two.by, code("2").code));
		expect([a1.judged, a2.judged]).toEqual([honestly, honestly]);
		// U: approval 2's code redeemed, its bundle making a family, while the approving key lives.
		const s2 = await place(flow, records.start(flow, "k6a-u", a2.id, code("2")));
		const b2 = await place(
			flow,
			records.bundle(flow, "k6a-u", { start: s2.id, root: a2.id }, tokensOf("k6a-u", true), {
				via: "code",
			}),
		);
		expect([s2.judged, b2.judged]).toEqual([honestly, honestly]);
		expect(
			await placed(
				flow,
				records.deletedKey(flow, "k6a-del", remove.by, remove.continuation, first),
			),
		).toEqual(honestly);
		// M: approval 1's start stands (the deletion drops no approval); its bundle's family does not.
		const s1 = await place(flow, records.start(flow, "k6a-m", a1.id, code("1")));
		expect(s1.judged).toEqual(honestly);
		expect(
			await placed(
				flow,
				records.bundle(flow, "k6a-m", { start: s1.id, root: a1.id }, tokensOf("k6a-m", true), {
					via: "code",
				}),
			),
		).toEqual(forged);
		await untaken(who, flow, keys);
	});

	it("K-6b: a family's refresh once its root key is deleted is forged, the one before taking (DEL_reg_noRootLive_ref)", async () => {
		const { who, keys } = await personWith(1);
		const [first] = keys as [string, string];
		const { flow } = await flowOf(core, first);
		const login = await heldLogin(core, who, rp, first);
		const remove = await heldDelete(core, who, first, first);
		const code = { via: "code", code: sha256("k6b-code"), client: rp.clientId } as const;
		const a = await place(flow, records.approval(flow, login.op, login.by, code.code));
		const s = await place(flow, records.start(flow, "k6b-login", a.id, code));
		const family = await place(
			flow,
			records.bundle(flow, "k6b-login", { start: s.id, root: a.id }, tokensOf("k6b-login", true), {
				via: "code",
			}),
		);
		expect([a.judged, s.judged, family.judged]).toEqual([honestly, honestly, honestly]);
		// U: the family's refresh at its rotation, while its root key lives.
		const at0 = { via: "refresh", rotation: 0 } as const;
		const r0 = await place(flow, records.start(flow, "k6b-u", family.id, at0));
		const r0b = await place(
			flow,
			records.bundle(
				flow,
				"k6b-u",
				{ start: r0.id, root: family.id },
				tokensOf("k6b-u", true),
				at0,
			),
		);
		expect([r0.judged, r0b.judged]).toEqual([honestly, honestly]);
		expect(
			await placed(
				flow,
				records.deletedKey(flow, "k6b-del", remove.by, remove.continuation, first),
			),
		).toEqual(honestly);
		// M: the same family's refresh at the rotation after U's.
		expect(
			await placed(flow, records.start(flow, "k6b-m", family.id, { via: "refresh", rotation: 1 })),
		).toEqual(forged);
		await untaken(who, flow, keys);
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 25, forged: 7, records: 39 }));
});
