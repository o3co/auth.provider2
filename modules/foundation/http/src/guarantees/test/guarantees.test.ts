import { describe, expect, it } from "vitest";
import { type PolicyMark, type PolicyUse, policy, type Route, use } from "../../contract.ts";
import { brokenGuarantees } from "../guarantees.ts";

const site = policy("test.site");
const limit = policy<{ readonly window: { readonly open: boolean } }>("test.limit");

const ownSite: PolicyMark = {
	guarantee: "own-site",
	policies: [{ policy: site, methods: ["POST", "PUT", "DELETE"] }],
};
const perSource: PolicyMark = {
	guarantee: "per-source",
	policies: [{ policy: limit, methods: ["GET", "POST", "PUT", "DELETE"] }],
};

const open = { window: { open: true } };
const answered = () => ({ status: 204 });
const post = (path: string, uses: readonly PolicyUse[], more: Partial<Route> = {}): Route => ({
	method: "POST",
	path,
	uses,
	handle: answered,
	...more,
});

/** The breaks of these routes against these marks, as [method and path, reason]. */
const breaks = (routes: readonly Route[], marks: readonly PolicyMark[] = [ownSite, perSource]) =>
	brokenGuarantees(routes, marks).map(({ route, reason }) => [
		`${route.method} ${route.path}`,
		reason,
	]);

describe("a route's declared guarantees", () => {
	it("finds no break in a route whose marked policies keep both, nor in a GET that changes nothing", () => {
		expect(
			breaks([
				post("/kept", [use(site), use(limit, open)], { changesState: true }),
				{ method: "GET", path: "/read", changesState: false, handle: answered },
			]),
		).toEqual([]);
	});

	it("counts a policy only by the mark of its own value, never by its name [guarantee-9-b]", () => {
		const named = policy("test.site");
		expect(breaks([post("/named", [use(named), use(limit, open)])])).toEqual([
			[
				"POST /named",
				"changes state with no policy marked own-site for POST, nor a reason in crossSite",
			],
		]);
	});

	it("asks a GET to say whether it changes state, and finds a POST said to change none", () => {
		expect(
			breaks([
				{ method: "GET", path: "/unsaid", unlimited: "counted by the handler", handle: answered },
				post("/said", [use(site), use(limit, open)], { changesState: false }),
			]),
		).toEqual([
			["GET /unsaid", "a GET route says whether it changes state (changesState)"],
			["POST /said", "a POST route changes state; changesState: false is for a GET"],
		]);
	});

	it("takes a mark only for the methods it names: a state-changing GET needs a reason [guarantee-9-b]", () => {
		const get = (uses: readonly PolicyUse[], more: Partial<Route>): Route => ({
			method: "GET",
			path: "/start",
			changesState: true,
			uses,
			handle: answered,
			...more,
		});
		expect(breaks([get([use(site), use(limit, open)], {})])).toEqual([
			[
				"GET /start",
				"changes state with no policy marked own-site for GET, nor a reason in crossSite",
			],
		]);
		const reasoned = get([use(limit, open)], { crossSite: "a navigation the user starts" });
		expect(breaks([reasoned])).toEqual([]);
	});

	it("finds a mark and a reason together, an empty reason, and a reason where nothing changes [guarantee-9-b]", () => {
		expect(
			breaks([
				post("/both", [use(site), use(limit, open)], { unlimited: "counted elsewhere" }),
				post("/empty", [use(limit, open)], { crossSite: " " }),
				{ method: "GET", path: "/still", changesState: false, crossSite: "x", handle: answered },
			]),
		).toEqual([
			["POST /both", "both a policy marked per-source for POST and a reason in unlimited"],
			["POST /empty", "an empty reason in crossSite"],
			["GET /still", "a reason in crossSite on a route that changes no state"],
		]);
	});

	it("finds its own-site policy after its per-source one, so a cross-site request spends no window", () => {
		expect(breaks([post("/late", [use(limit, open), use(site)], { changesState: true })])).toEqual([
			["POST /late", "its own-site policy runs after its per-source policy"],
		]);
	});

	it("checks a route that declares nothing as well: a GET must say, and any other must keep both or say why [guarantee-9-b] [guarantee-10-b] [oidc-core-3.1.2.3-e]", () => {
		expect(
			breaks([{ method: "GET", path: "/silent", handle: answered }, post("/bare", [])]),
		).toEqual([
			["GET /silent", "a GET route says whether it changes state (changesState)"],
			[
				"POST /bare",
				"changes state with no policy marked own-site for POST, nor a reason in crossSite",
			],
			[
				"POST /bare",
				"changes state with no policy marked per-source for POST, nor a reason in unlimited",
			],
		]);
	});

	it("finds every state-changing route broken where no mark is contributed", () => {
		expect(breaks([post("/unmarked", [use(site), use(limit, open)])], [])).toEqual([
			[
				"POST /unmarked",
				"changes state with no policy marked own-site for POST, nor a reason in crossSite",
			],
			[
				"POST /unmarked",
				"changes state with no policy marked per-source for POST, nor a reason in unlimited",
			],
		]);
	});
});
