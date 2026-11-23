import { defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { boot, refusalsOf } from "../../../test/boot.ts";
import {
	applying,
	marks,
	type PolicyMark,
	type PolicyRule,
	policies,
	policy,
	use,
} from "../../contract.ts";
import { testRequest } from "../../testing.ts";

describe("policies", () => {
	const gate = policy<{ readonly open: boolean }>("test.gate");

	it("makes a policy and a route's use of it frozen values", () => {
		expect([Object.isFrozen(gate), Object.isFrozen(use(gate, { open: true }))]).toEqual([
			true,
			true,
		]);
	});

	it("makes a rule for the policy's own value, given the options a route gives it", async () => {
		const rule = applying(gate, (_request, options) => (options.open ? "pass" : { status: 403 }));
		expect(rule.policy).toBe(gate);
		expect(rule.policy).not.toBe(policy("test.gate"));
		expect(await rule.apply(testRequest(), { open: true })).toBe("pass");
		expect(await rule.apply(testRequest(), { open: false })).toEqual({ status: 403 });
	});

	it("takes the rules of many owners at one point, and one mark per guarantee", async () => {
		const ownSite: PolicyMark = {
			guarantee: "own-site",
			policies: [{ policy: gate, methods: ["POST"] }],
		};
		const rule: PolicyRule = applying(gate, () => "pass");
		const owner = (name: string, mark: PolicyMark) =>
			defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
				m.contribute(policies).by(() => rule),
				m.contribute(marks).by(() => mark),
			]);
		await expect(boot({}, { modules: [owner("one", ownSite)] })).resolves.toBeDefined();
		const twice = [owner("one", ownSite), owner("two", ownSite)];
		expect(await refusalsOf(boot({}, { modules: twice }))).toEqual([
			["http.marks:own-site", "more than one contribution for the same key"],
		]);
	});
});
