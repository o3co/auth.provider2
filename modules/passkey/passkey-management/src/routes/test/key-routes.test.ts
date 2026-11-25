import { createHash, randomBytes } from "node:crypto";
import { continuations } from "@mod/continuation-wire";
import { overHttp } from "@mod/front-core-wire";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { sourceKey } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import type { ContinueAnswer, ContinueStage } from "../../contract.ts";
import type { Registered } from "../../registration/registration.ts";
import { continueRoute, keyRoutes, stagesOf } from "../routes.ts";

const b64 = (n: number) => randomBytes(n).toString("base64url");
const jws = `${b64(20)}.${b64(40)}.${b64(64)}`;

function routesOver(answer: Registered | (() => never)) {
	const asked: unknown[] = [];
	const give = async (q: unknown) => {
		asked.push(q);
		if (typeof answer === "function") answer();
		return answer as Registered;
	};
	const r = keyRoutes({ finish: give, window: { limit: 30, ms: 60_000 } });
	const post = (route: typeof r.keyFinish, json: Record<string, unknown>) =>
		route.handle(testRequest({ method: "POST", path: route.path, json }));
	return { r, asked, post };
}
const continued = { statement: jws, stage: "register", seq: "1", body: "{}", sig: b64(64) };

describe("a key's finish route", () => {
	it("serves /key/finish, counted per source, taking the screen's JSON across origins", () => {
		const { r } = routesOver({ kind: "refused", reason: "x" });
		expect(r.keyFinish.method).toBe("POST");
		expect(r.keyFinish.takes).toEqual(["json"]);
		expect(r.keyFinish.uses).toHaveLength(1);
		expect(r.keyFinish.cors).toBeDefined();
		expect(r.keyFinish.path).toBe("/key/finish");
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

/** `/continue` over stages each answering as told, recording what each was handed. */
function continueOver(answers: Partial<Record<string, ContinueAnswer>>) {
	const asked: unknown[] = [];
	const refusals: [string, string][] = [];
	const stages: ContinueStage[] = Object.entries(answers).map(([stage, answer]) => ({
		stage: stage as ContinueStage["stage"],
		continue: async (q) => {
			asked.push(q);
			return answer as ContinueAnswer;
		},
	}));
	const route = continueRoute({
		stages: stagesOf(stages, (reason) => {
			throw new Error(reason);
		}),
		window: { limit: 30, ms: 60_000 },
		refused: (stage, reason) => refusals.push([stage, reason]),
	});
	const post = (json: Record<string, unknown>) =>
		route.handle(testRequest({ method: "POST", path: route.path, json }));
	return { route, asked, refusals, post };
}
const sha = (text: string) => createHash("sha256").update(text).digest("base64url");

describe("`/continue`, each stage to the module that continues it", () => {
	it("is counted per source, taking the screen's JSON across origins", () => {
		const { route } = continueOver({});
		expect([route.method, route.path, route.takes, route.uses.length]).toEqual([
			"POST",
			"/continue",
			["json"],
			1,
		]);
	});

	it("hands a clear stage its continuation as read, with the statement's hash and the source, and answers its statement", async () => {
		const { asked, post } = continueOver({ register: { kind: "statement", statement: jws } });
		const answered = await post(continued);
		expect(answered.body).toEqual({ json: { statement: jws } });
		const request = testRequest({ method: "POST", path: "/continue", json: {} });
		expect(asked).toEqual([
			{
				stage: "register",
				statement: jws,
				hash: sha(jws),
				seq: 1,
				body: "{}",
				signature: continued.sig,
				source: sourceKey(request.source.address),
			},
		]);
	});

	it("hands a sealed stage its sealing, and answers its sealed value", async () => {
		const { asked, post } = continueOver({ delete: { kind: "sealed", enc: "E", ct: "C" } });
		const sealed = { statement: jws, stage: "delete", seq: "1", enc: b64(65), ct: b64(40) };
		expect((await post(sealed)).body).toEqual({ json: { sealed: { enc: "E", ct: "C" } } });
		expect(asked).toMatchObject([{ stage: "delete", sealed: { enc: sealed.enc, ct: sealed.ct } }]);
	});

	it("refuses fields of another size or spelling, and a stage none continues, as invalid", async () => {
		const { asked, post } = continueOver({
			register: { kind: "statement", statement: jws },
			delete: { kind: "sealed", enc: "E", ct: "C" },
		});
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
			// A clear stage sealed, and a sealed stage in the clear.
			{ enc: b64(65) },
			{ ct: b64(40) },
			{ stage: "delete" },
			{ stage: "other" },
			// A stage the wire names that no module here continues.
			{ stage: "sign-up" },
		]) {
			const answered = await post({ ...continued, ...wrong });
			expect(answered.status).toBe(400);
			expect((answered.body as { json: { error: string } }).json.error).toBe("invalid_request");
		}
		expect(asked).toEqual([]);
	});

	it("answers a refusal access_denied alone, its stage and reason told apart, and another form than the wire's a fault", async () => {
		const no = continueOver({ register: { kind: "refused", reason: "basis" } });
		expect((await no.post(continued)).body).toEqual({ json: { error: "access_denied" } });
		expect(no.refusals).toEqual([["register", "basis"]]);
		const odd = continueOver({ register: { kind: "sealed", enc: "E", ct: "C" } });
		await expect(odd.post(continued)).rejects.toThrow(TypeError);
	});

	it("asks of each stage the form front-core-wire gives it: a sealed value for a sealed stage, else a statement", async () => {
		const forms = (overHttp.operations.continue.answer as { forms: readonly string[] }).forms;
		for (const [at, stage] of continuations.stages.entries()) {
			const sealed = (continuations.sealed as readonly string[]).includes(stage);
			expect(forms[at]).toBe(sealed ? "sealed" : "statement");
		}
	});

	it("is refused at boot where two modules continue one stage", () => {
		const one: ContinueStage = {
			stage: "register",
			continue: async () => ({ kind: "refused", reason: "x" }),
		};
		expect(() =>
			stagesOf([one, one], (reason) => {
				throw new Error(reason);
			}),
		).toThrow("two modules continue the stage register");
	});
});
