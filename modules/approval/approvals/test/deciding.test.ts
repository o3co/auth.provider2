import {
	type Ask,
	allowed,
	effectOf,
	emptyState,
	type FlowState,
	timely,
} from "@mod/authority-rules";
import type { Stage } from "@mod/transparency";
import { ceremonies, keyThumbprint } from "@mod/webauthn";
import { testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { approvalKind, deciding } from "../src/completion/completion.ts";
import { recordOf } from "../src/statement/statement.ts";
import { screenKeys, sha256, world } from "./fixtures/world.ts";

const items = {
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "st",
	scope: "openid",
	nonce: "n",
	code_challenge: "cc",
	code_challenge_method: "S256",
	dpop_jkt: "jkt",
	jar_hash: "jh",
} as const;

/** A used authorization's record, and the flow state its key is live in. */
async function used() {
	const w = await world();
	const key = await w.plant("s1");
	const t = await w.approvals.issue({
		purpose: "authorization",
		items,
		screen: screenKeys().screen,
		by: "s",
	});
	if (t.kind !== "issued") throw new Error(t.reason);
	await w.approvals.use({ statement: t.statement, assertion: w.assert(t.challenge) });
	const r = recordOf(await w.statements.store.read(t.hash));
	if (!r) throw new Error("no record");
	// The flow state holds the key as it travels: its COSE_Key bytes.
	const live = {
		credential: key.id,
		publicKey: key.publicKey,
		chain: [],
		position: 1,
		acceptedAt: 0,
	};
	const state: FlowState = { ...emptyState, keys: { r0: live } };
	return { w, r, state, digest: (p: unknown) => sha256(JSON.stringify(p)) };
}

describe("an approval's KE-C01", () => {
	it("changes what authority-rules reads its record to change", async () => {
		const { w, r, state, digest } = await used();
		let stage: Stage | undefined;
		const decided = deciding(r, "code-1", digest, (made) => {
			stage = made;
		})(state, []);
		if ("refused" in decided || !stage) throw new Error("refused");
		const cer = await w.app.get(ceremonies);
		const signer = w.keys;
		const ask: Ask = {
			record: stage,
			preimage: stage.preimage,
			state,
			prior: [],
			checks: {
				verifyJws: (jws, ring) => signer.verifyJws(jws, ring),
				verifyAssertion: cer.verifyAssertion,
				keyThumbprint,
				digest: (data) =>
					sha256(typeof data === "string" ? data : Buffer.from(data).toString("latin1")),
			},
			context: {
				ring: signer.coreRing(1) ?? [],
				origin: testOrigin,
				limits: {
					codeLifetime: 60_000,
					refreshLifetime: 0,
					issueWindow: 0,
					epsilon: 0,
					propagation: 0,
					retry: 0,
				},
			},
		};
		expect(decided.eff).toEqual(effectOf(ask));
		expect(allowed(ask)).toEqual({ allowed: true });
		const iat = JSON.parse(Buffer.from(r.jws.split(".")[1] ?? "", "base64url").toString()).iat;
		expect(timely(ask, iat * 1000)).toBe(true);
		expect(timely(ask, r.exp + 1000)).toBe(false);
		expect(decided.eff).toMatchObject({
			approval: { key: "r0", code: sha256("code-1"), client: "c1" },
		});
		expect(decided.records).toEqual([]);
		expect(approvalKind.resend).toBeUndefined();
	});

	it("refuses a statement whose mark is set, and a key no longer live", async () => {
		const { r, state, digest } = await used();
		const decide = (s: FlowState) => deciding(r, "code-1", digest, () => {})(s, [undefined]);
		const mark = `statement:${r.sid}`;
		expect(decide({ ...state, consumed: [mark] })).toEqual({ refused: "used" });
		expect(decide({ ...state, keys: {} })).toEqual({ refused: "key" });
	});
});
