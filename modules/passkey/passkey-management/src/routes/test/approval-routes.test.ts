import { randomBytes } from "node:crypto";
import { testRequest } from "@mod/http/testing";
import { sourceKey } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import type { Finished, Started } from "../../approval/approval.ts";
import { approvalRoutes } from "../routes.ts";

const b64 = (n: number) => randomBytes(n).toString("base64url");
const jws = `${b64(20)}.${b64(40)}.${b64(64)}`;
const keys = { eEnc: b64(65), eSigX: b64(32), eSigY: b64(32) };

function routesOver(started: Started, finished: Finished) {
	const asked: unknown[] = [];
	const r = approvalRoutes({
		start: async (q) => {
			asked.push(q);
			return started;
		},
		finish: async (q) => {
			asked.push(q);
			return finished;
		},
		window: { limit: 30, ms: 60_000 },
	});
	const post = (route: typeof r.approvalStart, json: Record<string, unknown>) =>
		route.handle(testRequest({ method: "POST", path: route.path, json }));
	return { r, asked, post };
}

describe("a passkey-add's approval routes", () => {
	it("serve /approval/start and /approval/finish, counted per source, taking the screen's JSON across origins", () => {
		const { r } = routesOver(
			{ kind: "statement", statement: jws },
			{ kind: "refused", reason: "x" },
		);
		for (const route of [r.approvalStart, r.approvalFinish]) {
			expect(route.method).toBe("POST");
			expect(route.takes).toEqual(["json"]);
			expect(route.uses).toHaveLength(1);
			expect(route.cors).toBeDefined();
		}
		expect([r.approvalStart.path, r.approvalFinish.path]).toEqual([
			"/approval/start",
			"/approval/finish",
		]);
	});

	it("hands a start over with the screen's keys and its source's key, and answers its statement", async () => {
		const { r, asked, post } = routesOver(
			{ kind: "statement", statement: jws },
			{ kind: "refused", reason: "x" },
		);
		const answered = await post(r.approvalStart, { purpose: "passkey-add", ...keys });
		expect(answered.body).toEqual({ json: { statement: jws } });
		const request = testRequest({ method: "POST", path: "/approval/start", json: {} });
		expect(asked).toEqual([
			{
				purpose: "passkey-add",
				screen: {
					eEnc: keys.eEnc,
					eSig: { kty: "EC", crv: "P-256", x: keys.eSigX, y: keys.eSigY },
				},
				by: sourceKey(request.source.address),
			},
		]);
	});

	it("refuses a start of another purpose or keys of another size as invalid, and a refusal in one word", async () => {
		const { r, asked, post } = routesOver(
			{ kind: "refused", reason: "purpose" },
			{ kind: "refused", reason: "x" },
		);
		for (const wrong of [
			{ purpose: "other" },
			{ eEnc: b64(64) },
			{ eSigX: b64(33) },
			{ eSigY: `${b64(32)}=` },
			{ purpose: 0 },
		]) {
			const answered = await post(r.approvalStart, { purpose: "passkey-add", ...keys, ...wrong });
			expect(answered).toMatchObject({ status: 400, body: { json: { error: "invalid_request" } } });
		}
		expect(asked).toEqual([]);
		expect(await post(r.approvalStart, { purpose: "passkey-manage", ...keys })).toMatchObject({
			status: 400,
			body: { json: { error: "access_denied" } },
		});
	});

	it("answers a finish's completion sealed, any refusal access_denied alone, and fields of another size invalid", async () => {
		const done = routesOver(
			{ kind: "statement", statement: jws },
			{ kind: "completed", enc: "e", ct: "c" },
		);
		const finish = { statement: jws, assertion: "{}" };
		expect((await done.post(done.r.approvalFinish, finish)).body).toEqual({
			json: { sealed: { enc: "e", ct: "c" } },
		});
		expect(done.asked).toEqual([finish]);
		const no = routesOver(
			{ kind: "statement", statement: jws },
			{ kind: "refused", reason: "approver" },
		);
		expect(await no.post(no.r.approvalFinish, finish)).toMatchObject({
			status: 400,
			body: { json: { error: "access_denied" } },
		});
		for (const wrong of [{ statement: "a.b" }, { assertion: "" }, { assertion: "x".repeat(8193) }])
			expect(await no.post(no.r.approvalFinish, { ...finish, ...wrong })).toMatchObject({
				body: { json: { error: "invalid_request" } },
			});
	});
});
