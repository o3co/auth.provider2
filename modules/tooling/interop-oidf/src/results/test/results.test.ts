import { describe, expect, it } from "vitest";
import type { Expected } from "../../expected/expected.ts";
import type { Seen } from "../../screen/test/page.ts";
import {
	computedOf,
	judged,
	type ModuleRun,
	type Provider,
	refusalsOf,
	runJudged,
} from "./results.ts";

const at: Provider = {
	par: "https://issuer.test/oauth/par",
	token: "https://issuer.test/oauth/token",
	resource: "https://resource.test/resource",
	screen: "https://screen.test",
	parJarMaxLifetimeS: 90,
};
const variant = { openid: "openid_connect" };
const test = "fapi2-security-profile-final-happy-flow";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const now = 1_795_766_773;
const jar = (claims: unknown, header: unknown = { alg: "ES256", kid: "k" }) =>
	`${b64(header)}.${b64(claims)}.sig`;
const full = {
	iss: "c",
	client_id: "c",
	aud: "https://issuer.test",
	jti: "j",
	nbf: now,
	exp: now + 60,
	response_type: "code",
	response_mode: "form_post",
	redirect_uri: "https://rp/cb",
	scope: "openid",
	state: "s",
	nonce: "n",
	code_challenge: "x",
	code_challenge_method: "S256",
	dpop_jkt: "t",
};

/** The suite's log of one call: its block's start, the request and the answer. */
function called(
	block: string,
	id: string,
	url: string,
	status: string,
	body: string,
	request = "",
	headers = {},
) {
	return [
		{ src: "-START-BLOCK-", startBlock: "True", blockId: id, msg: block },
		{
			http: "request",
			src: "Call",
			blockId: id,
			request_uri: url,
			request_body: request,
			request_headers: headers,
			time: now * 1000,
		},
		{
			http: "response",
			src: "Call",
			blockId: id,
			response_status_code: status,
			response_body: body,
		},
	];
}
const words = (error: string, description: string) =>
	JSON.stringify({ error, error_description: description });
const typRefusal = words("invalid_request_object", "not of the typ asked");
const parBody = (claims: unknown, header?: unknown) =>
	`request=${jar(claims, header)}&client_assertion=a.b.c`;
const typLog = [
	...called(
		"Make request to PAR endpoint",
		"b1",
		at.par,
		"400 BAD_REQUEST",
		typRefusal,
		parBody(full),
	),
	{ result: "FAILURE", src: "CheckPAREndpointResponse201WithNoError", blockId: "b1" },
	{ result: "INTERRUPTED", src: test },
];
const run = (over: Partial<ModuleRun> = {}): ModuleRun => ({
	test,
	variant,
	status: "INTERRUPTED",
	result: "FAILED",
	log: typLog,
	...over,
});
const typ = {
	block: "Make request to PAR endpoint",
	refuser: "core",
	place: "par",
	status: 400,
	error: "invalid_request_object",
	description: "not of the typ asked",
	reading: "observed",
	keys: ["jar-typ-required"],
} as const;
const failure = { src: "CheckPAREndpointResponse201WithNoError", keys: ["jar-typ-required"] };
/** An object, a field given as undefined left out (an optional field absent, never undefined). */
const defined = (o: Record<string, unknown>) =>
	Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));
const entry = (over: { readonly [K in keyof Expected]?: unknown } = {}): Expected =>
	defined({
		test,
		variant,
		result: "FAILED",
		reading: "explained",
		refusals: [typ],
		failures: [failure],
		...over,
	}) as unknown as Expected;
const problems = (e: Expected | undefined, r: ModuleRun, seen: readonly Seen[] = []) =>
	judged(e, r, at, seen).problems.join("\n");

describe("a module's run, judged against its entry", () => {
	it("explains a failure its entry names by a key the run observes in its block, the computed keys beside", () => {
		const j = judged(entry(), run(), at, []);
		expect([j.class, j.problems, j.observed, j.computed]).toEqual([
			"explained",
			[],
			["jar-typ-required"],
			["jar-typ-required"],
		]);
	});

	it("classes a run before the wall, past it, and skipped as its entry reads", () => {
		const passed = run({ status: "FINISHED", result: "PASSED", log: typLog.slice(0, 3) });
		expect(
			judged(
				entry({ result: "PASSED", reading: "before-wall", failures: undefined }),
				passed,
				at,
				[],
			).class,
		).toBe("before-wall");
		const own = defined({
			...typ,
			refuser: "front",
			description: "request: fieldSyntax",
			reading: "own",
			keys: undefined,
		});
		const frontLog = called(
			"Make request to PAR endpoint",
			"b1",
			at.par,
			"400",
			words("invalid_request_object", "request: fieldSyntax"),
		);
		const ownEntry = entry({
			result: "PASSED",
			reading: "own-condition",
			failures: undefined,
			refusals: [own],
		});
		expect(
			judged(ownEntry, run({ status: "FINISHED", result: "PASSED", log: frontLog }), at, []).class,
		).toBe("crossed");
		const skipped = entry({
			result: "SKIPPED",
			reading: "skipped",
			refusals: [],
			failures: undefined,
		});
		expect(
			judged(skipped, run({ status: "FINISHED", result: "SKIPPED", log: [] }), at, []).class,
		).toBe("skipped");
	});

	it("fails a module whose run differs: a result, a refusal elsewhere, a condition, an unfinished run, no entry", () => {
		expect(problems(entry({ result: "WARNING" }), run())).toContain(
			"reported FAILED, its entry WARNING",
		);
		const elsewhere = entry({ refusals: [{ ...typ, block: "Another block" }] });
		expect(problems(elsewhere, run())).toContain("refusal is unused");
		expect(problems(elsewhere, run())).toContain("a refusal no entry names");
		const other = entry({ failures: [{ src: "Other", keys: ["jar-typ-required"] }] });
		expect(problems(other, run())).toContain("a FAILURE no entry names");
		expect(problems(other, run())).toContain("FAILURE is unused: Other");
		expect(problems(entry(), run({ status: "WAITING" }))).toContain("did not finish (WAITING)");
		expect(problems(undefined, run())).toContain("no entry names it");
		// A FAILURE under the module's own name is no summary: it is named, or it fails.
		expect(
			problems(entry(), run({ log: [...typLog, { result: "FAILURE", src: test }] })),
		).toContain(`a FAILURE no entry names: ${test}`);
	});

	it("fails a refusal read otherwise than its entry says, or by another refuser", () => {
		expect(
			problems(entry({ refusals: [defined({ ...typ, reading: "own", keys: undefined })] }), run()),
		).toContain("its entry own");
		expect(problems(entry({ refusals: [{ ...typ, refuser: "front" }] }), run())).toContain(
			"refusal is unused",
		);
	});

	it("explains a condition only by a key a refusal of its own block shows (decision 12)", () => {
		const client = words("invalid_client", "the client is not authenticated");
		const log = [
			...called("Client assertion 8 seconds ahead", "b2", at.par, "401", client),
			{ result: "WARNING", src: "CheckPAREndpointResponse201WithNoError", blockId: "b2" },
			...typLog,
		];
		const unconfirmed = {
			...typ,
			block: "Client assertion 8 seconds ahead",
			status: 401,
			error: "invalid_client",
			description: "the client is not authenticated",
			reading: "unconfirmed",
			keys: [],
		};
		const e = entry({ refusals: [unconfirmed, typ], warnings: [failure] });
		expect(problems(e, run({ log }))).toContain(
			"in Client assertion 8 seconds ahead is explained by jar-typ-required, which no refusal of its block shows",
		);
	});

	it("leaves unconfirmed a refusal no entry names whose words the table cannot tell apart; any other fails", () => {
		const log = [
			...typLog,
			...called(
				"Client assertion without sub",
				"b2",
				at.par,
				"401",
				words("invalid_client", "the client is not authenticated"),
			),
		];
		const j = judged(entry(), run({ log }), at, []);
		expect([j.class, j.unconfirmed]).toEqual([
			"unconfirmed",
			["Client assertion without sub: the client is not authenticated"],
		]);
		const log2 = [
			...typLog,
			...called("Another", "b3", at.par, "400", words("invalid_request", "something else")),
		];
		expect(judged(entry(), run({ log: log2 }), at, []).class).toBe("failed");
	});

	it("meets two refusals of one shape by their readings, whichever order they come in", () => {
		const jkt = words("invalid_request", "missing_item:dpop_jkt");
		const log = [
			...called("PAR", "b1", at.par, "400", jkt, "", { DPoP: "p" }),
			...called("PAR", "b2", at.par, "400", jkt, ""),
		];
		const base = {
			block: "PAR",
			refuser: "core",
			place: "par",
			status: 400,
			error: "invalid_request",
			description: "missing_item:dpop_jkt",
			reading: "observed",
		} as const;
		const e = entry({
			result: "PASSED",
			reading: "before-wall",
			failures: undefined,
			refusals: [
				{ ...base, keys: ["jar-dpop-jkt-required"] },
				{ ...base, keys: ["par-dpop-header-only"] },
			],
		});
		expect(problems(e, run({ status: "FINISHED", result: "PASSED", log }))).toBe("");
	});
});

describe("the refusals a run met", () => {
	it("reads who refused, the place by the URL, the resource as the harness's, and fails a refusal at no place", () => {
		const log = [
			...called(
				"PAR",
				"b1",
				at.par,
				"400",
				words("invalid_request_object", "request: fieldSyntax"),
			),
			...called("PAR", "b2", `${at.par}/`, "404", ""),
			...called("Token", "b3", at.token, "503", JSON.stringify({ error: "service_unavailable" })),
			...called(
				"Resource",
				"b4",
				`${at.resource}/x`,
				"401",
				words("invalid_dpop_proof", "the proof's signature"),
			),
			...called(
				"Discovery",
				"b5",
				"https://issuer.test/.well-known/openid-configuration",
				"500",
				"",
			),
			...called("Elsewhere", "b6", `${at.resource}-other/x`, "401", words("e", "d")),
		];
		const met = refusalsOf(run({ log }), at, []);
		expect(met.refusals.map((r) => [r.refuser, r.place, r.status])).toEqual([
			["front", "par", 400],
			["front", "par", 404],
			["unknown", "token", 503],
			["harness", "resource", 401],
		]);
		expect(met.problems).toEqual([
			"a refusal at no place the provider has: 500 https://issuer.test/.well-known/openid-configuration",
			"a refusal at no place the provider has: 401 https://resource.test/resource-other/x",
		]);
	});

	it("joins the screen's records to the module in order, by request_uri else state; its own stops fail the module", () => {
		const visit = (id: string, query: string) => [
			{ src: "-START-BLOCK-", startBlock: "True", blockId: id, msg: `Visit ${id}` },
			{
				src: "Redirect",
				blockId: id,
				redirect_to_authorization_endpoint: `${at.screen}/authorize?${query}`,
			},
		];
		const log = [
			...visit("v1", "request_uri=urn:1"),
			...visit("v2", "request_uri=urn:1"),
			...visit("v3", "state=st"),
			...visit("v4", "state=sdk"),
		];
		const refused = (over: Record<string, unknown>): Seen =>
			({
				kind: "refused",
				requestUri: undefined,
				state: undefined,
				refuser: "provider",
				at: "/login/start",
				status: 400,
				error: "invalid_request",
				description: "the request was used already",
				...over,
			}) as Seen;
		const seen: Seen[] = [
			{ kind: "started", requestUri: "urn:1" },
			refused({ requestUri: "urn:1" }),
			refused({ state: "st", description: "the request is sent by exactly one of its ways" }),
			refused({ state: "sdk", refuser: "sdk", at: "authorization.readPushed", stop: "statement" }),
		];
		const met = refusalsOf(run({ log }), at, seen);
		expect(met.refusals.map((r) => [r.block, r.place, r.carried ?? false])).toEqual([
			["Visit v2", "start", false],
			["Visit v3", "start", false],
		]);
		expect(met.refusals[0]?.reading).toEqual({ kind: "observed", key: "request-uri-once" });
		expect(met.problems).toEqual([
			"the screen role stopped: sdk at authorization.readPushed: statement",
		]);
	});
});

describe("the screen's records, as the pages write them", () => {
	const visit = (id: string, msg: string, query: string) => [
		{ src: "-START-BLOCK-", startBlock: "True", blockId: id, msg },
		{
			src: "Redirect",
			blockId: id,
			redirect_to_authorization_endpoint: `${at.screen}/authorize?${query}`,
		},
	];
	const finish = (over: Record<string, unknown> = {}): Seen =>
		({
			kind: "refused",
			requestUri: "urn:x:1",
			state: undefined,
			refuser: "provider",
			at: "/login/finish",
			status: 400,
			error: "login_required",
			description: "another subject",
			carried: true,
			...over,
		}) as Seen;

	it("gives a finish refused after its start, and a stop after it, to the visit that start opened", () => {
		const log = visit("v1", "Visit", "request_uri=urn:x:1");
		const met = refusalsOf(run({ log }), at, [
			{ kind: "started", requestUri: "urn:x:1" },
			finish(),
		]);
		expect(met.refusals.map((r) => [r.block, r.place, r.carried])).toEqual([
			["Visit", "finish", true],
		]);
		expect(met.problems).toEqual([]);
		const stopped = refusalsOf(run({ log }), at, [
			{ kind: "started", requestUri: "urn:x:1" },
			finish({ refuser: "page", at: "decide", stop: "neither approve nor deny" }),
		]);
		expect(stopped.problems).toEqual([
			"the screen role stopped: page at decide: neither approve nor deny",
		]);
	});

	it("keeps a start open past a revisit refused, and takes no visit for a record with no start, nor guesses between two", () => {
		const log = [
			...visit("v1", "First", "request_uri=urn:x:1"),
			...visit("v2", "Second", "request_uri=urn:x:1"),
			...visit("v3", "Third", "request_uri=urn:x:1"),
		];
		const refusedStart = finish({
			at: "/login/start",
			error: "invalid_request",
			description: "the request was used already",
			carried: undefined,
		});
		const met = refusalsOf(run({ log }), at, [
			{ kind: "started", requestUri: "urn:x:1" },
			refusedStart,
			finish(),
		]);
		expect(met.refusals.map((r) => [r.block, r.place])).toEqual([
			["Second", "start"],
			["First", "finish"],
		]);
		expect(met.problems).toEqual([]);
		expect(refusalsOf(run({ log }), at, [finish()]).problems).toEqual([
			"a screen record its visits cannot take (no start before it): /login/finish",
		]);
		const two = refusalsOf(run({ log }), at, [
			{ kind: "started", requestUri: "urn:x:1" },
			{ kind: "started", requestUri: "urn:x:1" },
			finish(),
		]);
		expect(two.problems).toEqual([
			"a screen record its visits cannot take (two starts open): /login/finish",
		]);
	});

	it("keys an empty request_uri by its state on both sides", () => {
		const log = visit("v1", "Visit", "request_uri=&state=st");
		const rec = {
			kind: "refused",
			requestUri: undefined,
			state: "st",
			refuser: "provider",
			at: "/login/start",
			status: 400,
			error: "x",
			description: "y",
		} as Seen;
		expect(refusalsOf(run({ log }), at, [rec]).refusals.map((r) => r.block)).toEqual(["Visit"]);
	});

	it("reads a screen record of no words as the Front's, words with no description as no one's", () => {
		const log = visit("v1", "Visit", "state=st");
		const rec = (over: Record<string, unknown>) =>
			({
				kind: "refused",
				requestUri: undefined,
				state: "st",
				refuser: "provider",
				at: "/login/start",
				status: 503,
				...over,
			}) as Seen;
		expect(refusalsOf(run({ log }), at, [rec({})]).refusals.map((r) => r.refuser)).toEqual([
			"front",
		]);
		expect(
			refusalsOf(run({ log }), at, [rec({ error: "temporarily_unavailable" })]).refusals.map(
				(r) => [r.refuser, r.reading.kind],
			),
		).toEqual([["unknown", "none"]]);
	});

	it("gives each record to the one module whose visits name its key; one of two modules', or of none, fails the run", () => {
		const a = run({ test: "a", log: visit("v1", "Visit", "state=both") });
		const b = run({ test: "b", log: visit("v2", "Visit", "state=both") });
		const rec = (state: string) =>
			({
				kind: "refused",
				requestUri: undefined,
				state,
				refuser: "provider",
				at: "/login/start",
				status: 400,
				error: "x",
				description: "y",
			}) as Seen;
		const judgedRun = runJudged([], [a, b], at, [rec("both"), rec("nowhere")]);
		expect(judgedRun.problems.filter((p) => p.startsWith("the screen's"))).toEqual([
			"the screen's record 1 (/login/start) is more than one module's",
			"the screen's record 2 (/login/start) is no module's visit",
		]);
	});

	it("explains a condition by its own block's id, never another block of the same message", () => {
		const log = [
			...called("Make request to PAR endpoint", "b1", at.par, "400", typRefusal, parBody(full)),
			...called(
				"Make request to PAR endpoint",
				"b2",
				at.par,
				"401",
				words("invalid_client", "the client is not authenticated"),
			),
			{ result: "FAILURE", src: "CheckPAREndpointResponse201WithNoError", blockId: "b2" },
		];
		const client = {
			...typ,
			status: 401,
			error: "invalid_client",
			description: "the client is not authenticated",
			reading: "unconfirmed",
			keys: [],
		};
		expect(problems(entry({ refusals: [typ, client] }), run({ log }))).toContain(
			"which no refusal of its block shows",
		);
	});
});

describe("a module's review", () => {
	const reviewLog = [
		{
			src: "-START-BLOCK-",
			startBlock: "True",
			blockId: "b9",
			msg: "Make request to authorization endpoint",
		},
		{
			src: "Build",
			blockId: "b9",
			redirect_to_authorization_endpoint: `${at.screen}/authorize?state=st1`,
		},
		{
			result: "REVIEW",
			src: "ExpectErrorPage",
			blockId: "b9",
			testId: "t1",
			msg: "m",
			page_source: "<p>refused</p>",
			content_type: "text/html",
		},
	];
	const seen: Seen[] = [
		{
			kind: "refused",
			requestUri: undefined,
			state: "st1",
			refuser: "provider",
			at: "/login/start",
			status: 400,
			error: "invalid_request",
			description: "the request is sent by exactly one of its ways",
		},
	];
	const startRefusal = {
		block: "Make request to authorization endpoint",
		refuser: "core",
		place: "start",
		status: 400,
		error: "invalid_request",
		description: "the request is sent by exactly one of its ways",
		reading: "unconfirmed",
		keys: ["jar-required"],
	} as const;
	const reviewEntry = entry({
		result: "REVIEW",
		reading: "unconfirmed",
		failures: undefined,
		refusals: [startRefusal],
	});
	const ran = (log: readonly unknown[]) => run({ status: "FINISHED", result: "REVIEW", log });

	it("records an unconfirmed review left unapproved, failing no run", () => {
		const j = judged(reviewEntry, ran(reviewLog), at, seen);
		expect([j.class, j.problems, j.reviews.map((r) => r.verdict)]).toEqual([
			"unconfirmed",
			[],
			["unconfirmed"],
		]);
	});

	it("takes the verdict from the class decided: a refusal its entry leaves unnamed, read unconfirmed, leaves the review unapproved", () => {
		const front = called(
			"Make request to PAR endpoint",
			"b1",
			at.par,
			"400",
			words("invalid_request_object", "request: fieldSyntax"),
		);
		const own = defined({
			...typ,
			refuser: "front",
			description: "request: fieldSyntax",
			reading: "own",
			keys: undefined,
		});
		const ownEntry = entry({
			result: "REVIEW",
			reading: "own-condition",
			failures: undefined,
			refusals: [own],
		});
		const kept = () => "/kept/page.html";
		expect(
			judged(ownEntry, ran([...front, ...reviewLog]), at, [], kept).reviews.map((r) => r.verdict),
		).toEqual(["approved"]);
		const j = judged(ownEntry, ran([...front, ...reviewLog]), at, seen, kept);
		expect([j.class, j.reviews.map((r) => r.verdict)]).toEqual(["unconfirmed", ["unconfirmed"]]);
	});

	it("fails a REVIEW with no page to stand on; a released page asks none", () => {
		const released = [
			...reviewLog.slice(0, 2),
			{ ...reviewLog[2], page_source: undefined, image_no_longer_required: true },
		];
		expect(problems(reviewEntry, ran(released), seen)).toContain(
			"a REVIEW with no page to stand on",
		);
		expect(problems(reviewEntry, ran(reviewLog.slice(0, 2)), seen)).toContain(
			"a REVIEW with no page to stand on",
		);
	});
});

describe("the keys a run's JARs compute", () => {
	it("names each envelope and item fault of a pushed JAR, by the DPoP header where it tells two rows apart", () => {
		const { state: _s, nonce: _n, dpop_jkt: _d, response_mode: _r, jti: _j, ...thin } = full;
		const log = called(
			"PAR",
			"b1",
			at.par,
			"400",
			typRefusal,
			parBody({ ...thin, exp: now + 300 }),
			{ DPoP: "p" },
		);
		expect(computedOf(run({ log }), at)).toEqual([
			"form-post-required",
			"jar-jti-required",
			"jar-typ-required",
			"nonce-required",
			"par-dpop-header-only",
			"par-jar-lifetime",
			"state-required",
		]);
		expect(computedOf(run({ log }), { ...at, parJarMaxLifetimeS: 360 })).not.toContain(
			"par-jar-lifetime",
		);
		const noHeader = called(
			"PAR",
			"b1",
			at.par,
			"400",
			typRefusal,
			parBody({ ...full, dpop_jkt: "" }),
		);
		expect(computedOf(run({ log: noHeader }), at)).toEqual([
			"jar-dpop-jkt-required",
			"jar-typ-required",
		]);
	});

	it("reads typ as the product does, and names no key for a JAR that is no object", () => {
		for (const typ of ["application/OAuth-Authz-Req+JWT; charset=UTF-8", " oauth-authz-req+jwt "]) {
			const log = called(
				"PAR",
				"b1",
				at.par,
				"400",
				typRefusal,
				parBody(full, { alg: "ES256", typ }),
			);
			expect(computedOf(run({ log }), at), typ).toEqual([]);
		}
		const nulls = called(
			"PAR",
			"b1",
			at.par,
			"400",
			typRefusal,
			`request=${b64(null)}.${b64(null)}.s`,
		);
		expect(computedOf(run({ log: nulls }), at)).toEqual([]);
	});
});

describe("a run judged", () => {
	it("passes where every module is judged and every entry ran, and fails otherwise", () => {
		expect(runJudged([entry()], [run()], at, []).passed).toBe(true);
		const missing = runJudged([entry(), entry({ test: "never-run" })], [run()], at, []);
		expect([missing.passed, missing.problems]).toEqual([
			false,
			["an entry no module ran: never-run"],
		]);
		const lost: Seen[] = [
			{
				kind: "refused",
				requestUri: undefined,
				state: "nowhere",
				refuser: "provider",
				at: "/login/start",
				status: 400,
				error: "x",
				description: "y",
			},
		];
		expect(runJudged([entry()], [run()], at, lost).problems).toEqual([
			"the screen's record 1 (/login/start) is no module's visit",
		]);
	});
});
