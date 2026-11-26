import { continuations } from "@mod/continuation-wire";
import { describe, expect, it } from "vitest";
import { screenKeys, sha256, world } from "../../../test/fixtures/world.ts";
import type { SignUpResult } from "../../contract.ts";

const items = {
	...{ client_id: "c1", redirect_uri: "https://rp.example/cb", response_type: "code" as const },
	...{ response_mode: "form_post" as const, state: "st", scope: "openid", nonce: "n" },
	...{ code_challenge: "cc", code_challenge_method: "S256" as const },
	...{ dpop_jkt: "jkt", jar_hash: "jh" },
};

describe("a T's sign-up, its hold lapsed", () => {
	it("is taken again only 2 seconds past its hold, so a hold lapsing in T's last 2 seconds runs no more", async () => {
		const w = await world();
		const keys = screenKeys();
		const t = await w.approvals.issue({
			...{ purpose: "authorization", items, screen: keys.screen, by: "src" },
			continues: ["sign-up"],
		});
		if (t.kind !== "issued") throw new Error(t.reason);
		const signature = keys.signs(continuations.of("sign-up", t.hash, 1, sha256("{}")));
		const signUp = (step: () => Promise<SignUpResult>) =>
			w.approvals.continueSignUp({ hash: t.hash, seq: 1, body: "{}", signature, step });
		// Taken 31 seconds before T expires: its hold ends a second before, the 2 seconds past it after.
		w.advance(5 * 60_000 - 31_000);
		await expect(
			signUp(async () => {
				throw new Error("fell");
			}),
		).rejects.toThrow("fell");
		const again = async (): Promise<SignUpResult> => ({ refused: "ledger" });
		const pending = { kind: "refused", reason: "pending" };
		w.advance(30_001);
		expect(await signUp(again)).toEqual(pending);
		// Its hold's end and 2 seconds: past T's expiry, still pending; a moment later, expired.
		w.advance(1_999);
		expect(await signUp(again)).toEqual(pending);
		w.advance(1);
		expect(await signUp(again)).toEqual({ kind: "refused", reason: "expired" });
	});
});
