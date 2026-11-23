import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	applying,
	type GuardedRoute,
	type HttpRequest,
	type PolicyMark,
	type PolicyRule,
	policy,
	type Route,
	use,
} from "../../contract.ts";
import { testRequest } from "../../testing.ts";
import { guardedRoutes } from "../guards.ts";

const answered = () => ({ status: 204 });
/** A test's route as the marks check it: a GET that changes no state, any other with a test's reasons. */
const declared = (route: Route): Route =>
	route.method === "GET"
		? { changesState: false, ...route }
		: { crossSite: "a test route", unlimited: "a test route", ...route };

/** The routes guarded by these rules and marks; throws when they are refused. */
function guarded(
	routes: readonly Route[],
	rules: readonly PolicyRule[],
	marks: readonly PolicyMark[] = [],
): readonly GuardedRoute[] {
	const checked = guardedRoutes(routes.map(declared), rules, marks);
	if (checked.kind !== "guarded") throw new Error(JSON.stringify(checked.refusals));
	return checked.routes;
}

/** The refusals of these routes, rules and marks, as [where, reason]. */
function refusals(
	routes: readonly Route[],
	rules: readonly PolicyRule[],
	marks: readonly PolicyMark[] = [],
) {
	const checked = guardedRoutes(routes, rules, marks);
	return checked.kind === "refused" ? checked.refusals.map((r) => [r.where, r.reason]) : [];
}

const guardOf = (route: GuardedRoute | undefined) => (request: HttpRequest) =>
	route?.guard ? route.guard(request) : Promise.resolve("pass" as const);

describe("route policies", () => {
	const gate = policy<{ readonly open: boolean }>("test.gate");
	const mark = policy("test.mark");
	const failing = policy("test.failing");

	it("applies the policies a route uses in its order, and the first that answers ends it", async () => {
		const seen: string[] = [];
		const rules = [
			applying(gate, (_request, options) => {
				seen.push(`gate ${options.open}`);
				return options.open ? "pass" : { status: 403 };
			}),
			applying(mark, () => {
				seen.push("mark");
				return "pass";
			}),
			applying(failing, async () => {
				throw new Unavailable("test");
			}),
		];
		const [open, shut, fails] = guarded(
			[
				{
					method: "GET",
					path: "/open",
					uses: [use(mark), use(gate, { open: true })],
					handle: answered,
				},
				{
					method: "GET",
					path: "/shut",
					uses: [use(gate, { open: false }), use(mark)],
					handle: answered,
				},
				{ method: "GET", path: "/failing", uses: [use(failing)], handle: answered },
			],
			rules,
		);
		expect(await guardOf(open)(testRequest())).toBe("pass");
		expect(seen).toEqual(["mark", "gate true"]);
		seen.length = 0;
		expect(await guardOf(shut)(testRequest())).toEqual({ status: 403 });
		expect(seen).toEqual(["gate false"]);
		await expect(guardOf(fails)(testRequest())).rejects.toThrow(Unavailable);
	});

	it("leaves a route that uses no policy unguarded", () => {
		const route: Route = { method: "GET", path: "/plain", changesState: false, handle: answered };
		const checked = guardedRoutes([route], [], []);
		expect(checked.kind === "guarded" && checked.routes[0]).toBe(route);
	});

	it("refuses a route that uses a policy no module applies, naming the route and the policy", () => {
		const routes = [
			// Named like a policy that has a rule, yet another value: matched by value, it has none.
			declared({
				method: "POST",
				path: "/lonely",
				uses: [use(policy("test.mark"))],
				handle: answered,
			}),
			declared({ method: "GET", path: "/alone", uses: [use(failing)], handle: answered }),
		];
		expect(refusals(routes, [applying(mark, () => "pass")])).toEqual([
			["http.routes:POST /lonely", "uses a policy no module applies: test.mark"],
			["http.routes:GET /alone", "uses a policy no module applies: test.failing"],
		]);
	});

	it("keeps two policies of the same name from different owners apart", async () => {
		const theirs = policy("shared.name");
		const ours = policy("shared.name");
		const [first, second] = guarded(
			[
				{ method: "GET", path: "/theirs", uses: [use(theirs)], handle: answered },
				{ method: "GET", path: "/ours", uses: [use(ours)], handle: answered },
			],
			[applying(theirs, () => ({ status: 401 })), applying(ours, () => "pass")],
		);
		expect(await guardOf(first)(testRequest())).toEqual({ status: 401 });
		expect(await guardOf(second)(testRequest())).toBe("pass");
	});

	it("refuses two rules for one policy", () => {
		const ours = policy("shared.name");
		expect(refusals([], [applying(ours, () => "pass"), applying(ours, () => "pass")])).toEqual([
			["http.policies", "more than one rule for a policy: shared.name"],
		]);
	});

	it("gives a policy a frozen copy of what the route gave it when guarded, whatever is changed afterwards", async () => {
		const window = { open: true };
		const given: unknown[] = [];
		const limit = policy<{ readonly window: { open: boolean } }>("test.limit");
		const [route] = guarded(
			[{ method: "GET", path: "/fixed", uses: [use(limit, { window })], handle: answered }],
			[
				applying(limit, (_request, options) => {
					given.push(options);
					return options.window.open ? "pass" : { status: 429 };
				}),
			],
		);
		window.open = false;
		expect(await guardOf(route)(testRequest())).toBe("pass");
		expect(Object.isFrozen((given[0] as { window: object }).window)).toBe(true);
	});

	it("refuses the routes that break what they declare against the marks, naming each route", () => {
		const site = policy("test.site");
		const ownSite: PolicyMark = {
			guarantee: "own-site",
			policies: [{ policy: site, methods: ["POST"] }],
		};
		const routes: Route[] = [
			{ method: "GET", path: "/silent", handle: answered },
			{
				method: "POST",
				path: "/kept",
				uses: [use(site)],
				unlimited: "a test route",
				handle: answered,
			},
		];
		expect(refusals(routes, [applying(site, () => "pass")], [ownSite])).toEqual([
			["http.routes:GET /silent", "a GET route says whether it changes state (changesState)"],
		]);
	});
});
