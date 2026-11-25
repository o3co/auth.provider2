import { randomBytes } from "node:crypto";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Continuation, Registered } from "../../registration/registration.ts";
import { keyRoutes } from "../routes.ts";

const b64 = (n: number) => randomBytes(n).toString("base64url");
const jws = `${b64(20)}.${b64(40)}.${b64(64)}`;

function routesOver(answer: Registered | (() => never)) {
	const asked: unknown[] = [];
	const give = async (q: unknown) => {
		asked.push(q);
		if (typeof answer === "function") answer();
		return answer as Registered;
	};
	const r = keyRoutes({ register: give, finish: give, window: { limit: 30, ms: 60_000 } });
	const post = (route: typeof r.continue, json: Record<string, unknown>) =>
		route.handle(testRequest({ method: "POST", path: route.path, json }));
	return { r, asked, post };
}
const continued = { statement: jws, stage: "register", seq: "1", body: "{}", sig: b64(64) };

describe("a key's registration routes", () => {
	it("serve /continue and /key/finish, counted per source, taking the screen's JSON across origins", () => {
		const { r } = routesOver({ kind: "refused", reason: "x" });
		for (const route of [r.continue, r.keyFinish]) {
			expect(route.method).toBe("POST");
			expect(route.takes).toEqual(["json"]);
			expect(route.uses).toHaveLength(1);
			expect(route.cors).toBeDefined();
		}
		expect([r.continue.path, r.keyFinish.path]).toEqual(["/continue", "/key/finish"]);
	});

	it("hands a register continuation over as read, and answers its possession", async () => {
		const { r, asked, post } = routesOver({ kind: "possession", statement: jws });
		const answered = await post(r.continue, continued);
		expect(answered.body).toEqual({ json: { statement: jws } });
		expect(asked).toEqual([
			{ statement: jws, seq: 1, body: "{}", sig: continued.sig } satisfies Continuation,
		]);
	});

	it("refuses fields of another size or spelling as invalid, a stage not taken here too", async () => {
		const { r, asked, post } = routesOver({ kind: "possession", statement: jws });
		for (const wrong of [
			{ seq: "0" },
			{ seq: "17" },
			{ seq: "01" },
			{ sig: b64(63) },
			{ body: "" },
			{ body: "x".repeat(8193) },
			{ statement: "a.b" },
			{ enc: null },
			{ ct: [] },
			{ seq: 1 },
			{ enc: b64(65) },
			{ ct: b64(40) },
			{ stage: "delete" },
			{ stage: "other" },
		]) {
			const answered = await post(r.continue, { ...continued, ...wrong });
			expect(answered.status).toBe(400);
			expect((answered.body as { json: { error: string } }).json.error).toBe("invalid_request");
		}
		expect(asked).toEqual([]);
	});

	it("answers a finish's completion sealed, any refusal access_denied alone, and a fault unavailable", async () => {
		const done = routesOver({ kind: "completed", enc: "E", ct: "C" });
		const finish = { statement: jws, assertion: "{}" };
		expect((await done.post(done.r.keyFinish, finish)).body).toEqual({
			json: { sealed: { enc: "E", ct: "C" } },
		});
		expect((await done.post(done.r.keyFinish, { statement: jws })).status).toBe(400);
		expect((await done.post(done.r.keyFinish, { ...finish, extra: null })).status).toBe(400);
		const refused = routesOver({ kind: "refused", reason: "reservation" });
		expect((await refused.post(refused.r.keyFinish, finish)).body).toEqual({
			json: { error: "access_denied" },
		});
		const down = routesOver(() => {
			throw new Unavailable("x");
		});
		await expect(down.post(down.r.keyFinish, finish)).rejects.toThrow(Unavailable);
	});
});
