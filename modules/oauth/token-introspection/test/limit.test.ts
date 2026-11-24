import { expect, it } from "vitest";
import { section } from "../src/section.ts";
import { serve } from "./serve.ts";

it("limits requests per source, before any client is authenticated [rfc6749-2.3.1-c] [guarantee-10-a]", async () => {
	const s = await serve({ limit: { requests: 2, window: "1m" } });
	const wrong = { token: await s.issue(), client_id: "api", client_secret: "wrong" };
	for (let i = 0; i < 2; i++) {
		expect((await s.post(undefined, wrong)).status).toBe(401);
	}
	const limited = await s.post(undefined, wrong);
	expect([limited.status, limited.headers.get("retry-after"), limited.json]).toEqual([
		429,
		"60",
		{ error: "rate_limited" },
	]);
});

it("counts 60 requests per minute unless set, taking the window only with its unit, in whole seconds", () => {
	expect(section.parse({})).toEqual({ requests: 60, window: 60 });
	const takes = (window: unknown) => section.safeParse({ window }).success;
	expect(["1s", "1d", "86401s", 60, "1500ms"].map(takes)).toEqual([
		true,
		true,
		false,
		false,
		false,
	]);
});
