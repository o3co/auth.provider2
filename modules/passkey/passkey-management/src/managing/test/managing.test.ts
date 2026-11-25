import type { Approvals, KeptManage, OpenedBody, StepResult } from "@mod/approvals";
import { describe, expect, it } from "vitest";
import type { ContinueAsk } from "../../contract.ts";
import { renameStageOver } from "../managing.ts";

const kept: KeptManage = {
	hash: "H",
	subject: "s1",
	credential: "approver",
	registration: "r0",
	screen: { eEnc: "E", eSig: { kty: "EC", crv: "P-256", x: "x", y: "y" } },
	until: 9,
};
const opened: OpenedBody = {
	stage: "rename",
	body: { credential_id: "k2", label: "Laptop" },
	bodyHash: "B",
};
const ask = {
	stage: "rename",
	source: "src",
	statement: "a.b.c",
	hash: "H",
	seq: 2,
	sealed: { enc: "e", ct: "c" },
} as ContinueAsk;

/** The stage over approvals that run its step at once and keep what it answers. */
function stage(
	o: { approver?: string; renamed?: string; listed?: string; body?: OpenedBody["body"] } = {},
) {
	const renames: unknown[] = [];
	const asked: unknown[] = [];
	const approvals = {
		continueSealed: async (q: Parameters<Approvals["continueSealed"]>[0]) => {
			const result: StepResult = await q.step(kept, { ...opened, body: o.body ?? opened.body });
			return { kind: "continued", seq: q.seq, again: false, result } as const;
		},
		completePasskeyManage: async (q: unknown) => {
			asked.push(q);
			return o.listed === undefined
				? ({ kind: "completed", enc: "LE", ct: "LC" } as const)
				: ({ kind: "refused", reason: o.listed } as never);
		},
	};
	const renameStage = renameStageOver({
		approvals,
		passkeys: {
			publicKeyOf: async () => ({
				subject: "s1",
				publicKey: "p",
				registration: o.approver ?? "r0",
			}),
		},
		keys: {
			rename: async (q) => {
				renames.push(q);
				return (o.renamed ?? "renamed") as never;
			},
		},
	});
	return { renameStage, renames, asked };
}

describe("a passkey-manage's rename", () => {
	it("renames the key it names by the statement, its number and its end, then answers the list", async () => {
		const s = stage();
		expect(await s.renameStage.continue(ask)).toEqual({ kind: "sealed", enc: "LE", ct: "LC" });
		expect(s.renames).toEqual([
			{
				subject: "s1",
				credential: "k2",
				label: "Laptop",
				by: { statement: "H", seq: 2, until: 9 },
			},
		]);
		expect(s.asked).toEqual([{ hash: "H", continued: { stage: "rename", seq: 2, bodyHash: "B" } }]);
	});

	it("answers the list unchanged for a key none of the subject's, or a later rename's", async () => {
		for (const renamed of ["unknown", "stale"]) {
			const s = stage({ renamed });
			expect(await s.renameStage.continue(ask)).toMatchObject({ kind: "sealed" });
			expect(s.asked).toHaveLength(1);
		}
	});

	it("renames nothing where the approving key is gone or registered again", async () => {
		const s = stage({ approver: "r9" });
		expect(await s.renameStage.continue(ask)).toEqual({ kind: "refused", reason: "approver" });
		expect(s.renames).toEqual([]);
	});

	it("answers a list's refusal in its word, and throws a ring withdrawn, a label refused, a rename in the clear", async () => {
		expect(await stage({ listed: "expired" }).renameStage.continue(ask)).toEqual({
			kind: "refused",
			reason: "expired",
		});
		await expect(stage({ listed: "withdrawn" }).renameStage.continue(ask)).rejects.toThrow();
		await expect(stage({ renamed: "label" }).renameStage.continue(ask)).rejects.toThrow(TypeError);
		const { sealed: _, ...common } = ask as { sealed: unknown };
		const clear = { ...common, body: "{}", signature: "s" } as unknown as ContinueAsk;
		await expect(stage().renameStage.continue(clear)).rejects.toThrow(TypeError);
	});
});
