import { payloads } from "@mod/sdk-core-wire";
import { expect, it } from "vitest";
import { screenKeys, world } from "../../../test/fixtures/world.ts";

const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

it("issues a passkey-manage as a passkey-add, used by an assertion alone, and no passkey-add", async () => {
	const w = await world();
	const key = await w.plant("s1");
	const { screen } = screenKeys();
	const a = await w.approvals.issue({ purpose: "passkey-manage", items: {}, screen, by: "src" });
	if (a.kind !== "issued") throw new Error(a.reason);
	const payload = payloadOf(a.statement);
	expect(payloads.passkeyManage.safeParse(payload).success).toBe(true);
	expect(payload).not.toHaveProperty("passkey-manage");
	expect(await w.approvals.use({ statement: a.statement, verification: "v1" })).toEqual({
		kind: "refused",
		reason: "purpose",
	});
	const assertion = w.assert(a.challenge);
	expect(await w.approvals.use({ statement: a.statement, assertion })).toMatchObject({
		kind: "approved",
		approval: {
			hash: a.hash,
			purpose: "passkey-manage",
			items: {},
			subject: "s1",
			credential: key.id,
			registration: "r0",
		},
	});
	expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
});
