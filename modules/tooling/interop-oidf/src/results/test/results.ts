/**
 * A run's results: each module's run read against its expected entry, in the ledger's keys. It reads
 * sdk-core-wire's items and external-jwt's typ, so its files are tests'.
 */
import { typOf } from "@mod/external-jwt";
import { itemsFromJar, jarClaims } from "@mod/sdk-core-wire";
import type { Expected, ExpectedRefusal } from "../../expected/expected.ts";
import {
	type Reviewed,
	type ReviewPage,
	reviewed,
	reviewPagesOf,
	type Verdict,
} from "../../review/review.ts";
import type { Seen as PageSeen } from "../../screen/test/page.ts";
import { type Place, type Reading, type Refuser, readingOf, refuserOf } from "../../words/words.ts";

/** One module as the suite ran it: its info's status and result, and its log. */
export interface ModuleRun {
	readonly test: string;
	readonly variant: Readonly<Record<string, string>>;
	readonly status: string;
	readonly result: string | undefined;
	readonly log: readonly unknown[];
}

/** The provider a run met: its PAR, token and resource URLs, the screen's origin, and PAR's longest JAR lifetime. */
export interface Provider {
	readonly par: string;
	readonly token: string;
	readonly resource: string;
	readonly screen: string;
	readonly parJarMaxLifetimeS: number;
}

/** A refusal the run met: where (its block's message and id, the place), its status and words, who answered (`unknown` where its words cannot say), what the table reads. */
export interface RunRefusal {
	readonly block: string;
	readonly blockId: string;
	readonly place: Place;
	readonly status: number;
	readonly error?: string;
	readonly description?: string;
	readonly refuser: Refuser | "unknown";
	readonly reading: Reading;
	readonly carried?: true;
}

/** A module's class: `crossed` (to its end, or on its own condition), `before-wall` (no evidence), `explained`, `unconfirmed`, `skipped`, or `failed` (the run fails). */
export type Class = "crossed" | "before-wall" | "explained" | "unconfirmed" | "skipped" | "failed";

/** A FAILURE or WARNING a module met: its condition, where it was logged, whether its entry names it, the keys it gives, and those of them no refusal of its block shows. */
export interface MetCondition {
	readonly kind: "FAILURE" | "WARNING";
	readonly src: string;
	readonly block: string;
	readonly blockId: string;
	readonly named: boolean;
	readonly keys: readonly string[];
	readonly unshown: readonly string[];
}

/** A module judged: its class, its blocks in the log's order, the refusals and conditions met, the keys observed and computed, what failed it, the unconfirmed, the reviews. */
export interface Judged {
	readonly test: string;
	readonly variant: Readonly<Record<string, string>>;
	readonly result: string | undefined;
	readonly class: Class;
	readonly blocks: readonly { readonly id: string; readonly message: string }[];
	readonly refusals: readonly RunRefusal[];
	readonly conditions: readonly MetCondition[];
	readonly observed: readonly string[];
	readonly computed: readonly string[];
	readonly problems: readonly string[];
	readonly unconfirmed: readonly string[];
	readonly reviews: readonly Reviewed[];
}

/** The refusals a module met, and what of them fails it. */
export interface Met {
	readonly refusals: readonly RunRefusal[];
	readonly problems: readonly string[];
}

type Entry = Record<string, unknown>;
const isEntry = (v: unknown): v is Entry =>
	typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);
const path = (url: string) => (url.split(/[?#]/)[0] ?? url).replace(/\/$/, "");

const placeOf = (url: string, at: Provider): Place | undefined => {
	const p = path(url);
	if (p === path(at.par)) return "par";
	if (p === path(at.token)) return "token";
	const resource = path(at.resource);
	return p === resource || p.startsWith(`${resource}/`) ? "resource" : undefined;
};

const headerOf = (headers: unknown, name: string) =>
	isEntry(headers)
		? Object.entries(headers).find(([k]) => k.toLowerCase() === name)?.[1]
		: undefined;

/** Each request the log holds with its answer (paired by condition and block, each request once). */
function exchangesOf(log: readonly unknown[]) {
	const asked = new Map<string, Entry>();
	const out: { request: Entry; response: Entry }[] = [];
	for (const e of log.filter(isEntry)) {
		const by = `${String(e.src)} ${String(e.blockId)}`;
		if (e.http === "request") asked.set(by, e);
		const request = asked.get(by);
		if (e.http === "response" && request !== undefined) {
			out.push({ request, response: e });
			asked.delete(by);
		}
	}
	return out;
}

/** Where a condition outside every block was logged; a refusal there has no block's message, so no entry names it. */
const noBlock = "no block";
const blocksOf = (log: readonly unknown[]) =>
	new Map(
		log
			.filter(isEntry)
			.filter((e) => e.startBlock !== undefined)
			.map((e) => [String(e.blockId), String(e.msg)]),
	);

/** Who refused and what the table reads, from its place and words: the harness at the resource, the Front for no words, `unknown` for words with no description. */
function readOf(
	place: Place,
	words: { error?: string; description?: string } | undefined,
	dpopHeader: boolean,
	startedBefore = false,
) {
	const refuser: Refuser | "unknown" =
		place === "resource"
			? "harness"
			: words?.error === undefined
				? "front"
				: words.description === undefined
					? "unknown"
					: refuserOf(words.description);
	const reading: Reading =
		refuser === "unknown" || words?.error === undefined || words.description === undefined
			? { kind: "none" }
			: readingOf({
					refuser,
					place,
					error: words.error,
					description: words.description,
					dpopHeader,
					startedBefore,
				});
	return { refuser, reading };
}

const wordsOf = (body: unknown) => {
	try {
		const j = JSON.parse(typeof body === "string" ? body : "");
		if (!isEntry(j) || typeof j.error !== "string") return undefined;
		return typeof j.error_description === "string"
			? { error: j.error, description: j.error_description }
			: { error: j.error };
	} catch {
		return undefined;
	}
};

/** A visit's key, the same on both sides: its request_uri where it names one, else its state. */
const keyOf = (requestUri: string | null | undefined, state: string | null | undefined) =>
	requestUri !== undefined && requestUri !== null && requestUri !== ""
		? requestUri
		: `state:${state ?? ""}`;

const keyOfSeen = (s: PageSeen) => keyOf(s.requestUri, s.kind === "refused" ? s.state : undefined);

/** The visits a module's log sent the browser to, on the screen's origin, by key, in order: each its block. */
function visitsOf(run: ModuleRun, at: Provider) {
	const queues = new Map<string, { block: string; blockId: string }[]>();
	const blocks = blocksOf(run.log);
	for (const e of run.log.filter(isEntry)) {
		const url = str(e.redirect_to_authorization_endpoint);
		if (url === undefined) continue;
		try {
			const u = new URL(url);
			if (u.origin !== new URL(at.screen).origin) continue;
			const key = keyOf(u.searchParams.get("request_uri"), u.searchParams.get("state"));
			const blockId = String(e.blockId);
			queues.set(key, [...(queues.get(key) ?? []), { block: blocks.get(blockId) ?? "", blockId }]);
		} catch {}
	}
	return queues;
}

/**
 * The screen's records for one module, in order: a start (`started`, a refused `/login/start`, a stop with
 * none open) takes the next visit of its key and opens it; a finish or a decision is its one open visit's
 * (none open, or two, fails the module; the page records no decision that went through, so a visit stays
 * open after it). A provider's refused start or finish is a refusal; any other stop fails the module.
 */
function screenOf(run: ModuleRun, at: Provider, seen: readonly PageSeen[]): Met {
	const queues = visitsOf(run, at);
	const open = new Map<string, { block: string; blockId: string }[]>();
	const everStarted = new Set<string>();
	const refusals: RunRefusal[] = [];
	const problems: string[] = [];
	for (const s of seen) {
		const key = keyOfSeen(s);
		const opened = open.get(key) ?? [];
		// A finish or a decision is after its start alone; another stop is a start's where none is open.
		const afterStart = s.kind === "refused" && (s.at === "/login/finish" || s.at === "decide");
		const isStart =
			s.kind === "started" || s.at === "/login/start" || (!afterStart && opened.length === 0);
		// A later record is its start's: one open visit of the key alone, never a fresh one, never a guess between two.
		const visit = isStart ? queues.get(key)?.shift() : opened.length === 1 ? opened[0] : undefined;
		if (visit === undefined) {
			const why = isStart
				? "no visit left"
				: opened.length === 0
					? "no start before it"
					: "two starts open";
			problems.push(
				`a screen record its visits cannot take (${why}): ${s.kind === "refused" ? s.at : s.kind}`,
			);
			continue;
		}
		if (s.kind === "started") {
			open.set(key, [...opened, visit]);
			everStarted.add(key);
			continue;
		}
		const startedBefore = isStart && everStarted.has(key);
		if (!isStart) open.delete(key);
		const place: Place | undefined =
			s.at === "/login/start" ? "start" : s.at === "/login/finish" ? "finish" : undefined;
		if (s.refuser !== "provider" || place === undefined) {
			problems.push(
				`the screen role stopped: ${s.refuser} at ${s.at}: ${s.stop ?? s.description ?? ""}`,
			);
			continue;
		}
		const words =
			s.error === undefined
				? undefined
				: {
						error: s.error,
						...(s.description === undefined ? {} : { description: s.description }),
					};
		const { refuser, reading } = readOf(place, words, false, startedBefore);
		refusals.push({
			...visit,
			place,
			status: s.status ?? 0,
			...words,
			refuser,
			reading,
			...(s.carried ? { carried: true as const } : {}),
		});
	}
	return { refusals, problems };
}

/** The refusals a module's run met, and what of them fails it: a refusal at no place the provider has, the screen's records (those of this module alone). */
export function refusalsOf(run: ModuleRun, at: Provider, seen: readonly PageSeen[]): Met {
	const blocks = blocksOf(run.log);
	const refusals: RunRefusal[] = [];
	const problems: string[] = [];
	for (const { request, response } of exchangesOf(run.log)) {
		const status = Number.parseInt(String(response.response_status_code), 10);
		if (!(status >= 400)) continue;
		const url = String(request.request_uri ?? "");
		const place = placeOf(url, at);
		if (place === undefined) {
			problems.push(`a refusal at no place the provider has: ${status} ${path(url)}`);
			continue;
		}
		const blockId = String(response.blockId);
		const words = wordsOf(response.response_body);
		const { refuser, reading } = readOf(
			place,
			words,
			headerOf(request.request_headers, "dpop") !== undefined,
		);
		refusals.push({
			block: blocks.get(blockId) ?? "",
			blockId,
			place,
			status,
			...words,
			refuser,
			reading,
		});
	}
	const screen = screenOf(run, at, seen);
	return {
		refusals: [...refusals, ...screen.refusals],
		problems: [...problems, ...screen.problems],
	};
}

/** The ledger keys a module's pushed JARs compute: the envelope (typ absent, jti, lifetime) and the items as sdk-core-wire reads them. */
export function computedOf(run: ModuleRun, at: Provider): string[] {
	const keys = new Set<string>();
	for (const { request } of exchangesOf(run.log)) {
		if (placeOf(String(request.request_uri ?? ""), at) !== "par") continue;
		const [head, body] = (
			new URLSearchParams(String(request.request_body ?? "")).get("request") ?? ""
		).split(".");
		let header: unknown;
		let claims: unknown;
		try {
			header = JSON.parse(Buffer.from(head ?? "", "base64url").toString());
			claims = JSON.parse(Buffer.from(body ?? "", "base64url").toString());
		} catch {
			continue;
		}
		if (!isEntry(header) || !isEntry(claims)) continue;
		const dpopHeader = headerOf(request.request_headers, "dpop") !== undefined;
		if (typOf(header) === undefined) keys.add("jar-typ-required");
		if (typeof claims.jti !== "string" || claims.jti === "") keys.add("jar-jti-required");
		if (
			typeof claims.exp === "number" &&
			claims.exp - Number(request.time) / 1000 > at.parJarMaxLifetimeS
		)
			keys.add("par-jar-lifetime");
		const given = (k: string) => typeof claims[k] === "string" && claims[k] !== "";
		const spelled = jarClaims.required.filter((k) => !given(k)).map((k) => `missing_item:${k}`);
		const filled = Object.fromEntries(
			jarClaims.required.map((k) => [k, given(k) ? claims[k] : "x"]),
		);
		const rest = itemsFromJar({ ...claims, ...filled }, "x");
		if ("error" in rest) spelled.push(rest.error);
		for (const description of spelled)
			for (const error of ["invalid_request", "invalid_request_object"]) {
				const r = readingOf({
					refuser: "core",
					place: "par",
					error,
					description,
					dpopHeader,
					startedBefore: false,
				});
				if (r.kind === "observed") keys.add(r.key);
			}
	}
	return [...keys].sort();
}

const shape = (
	r: Pick<ExpectedRefusal, "block" | "place" | "status" | "error" | "description"> & {
		readonly refuser: string;
	},
) =>
	JSON.stringify([r.block, r.place, r.status, r.refuser, r.error ?? null, r.description ?? null]);

const sameKeys = (a: readonly string[], b: readonly string[]) =>
	JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

/** Whether what the table reads of a run's refusal is what its entry said. */
const readAs = (e: ExpectedRefusal, r: Reading) =>
	e.reading === "observed"
		? r.kind === "observed" && r.key === e.keys?.[0]
		: e.reading === "own"
			? r.kind === "none"
			: r.kind === "unconfirmed" && (e.keys === undefined || sameKeys(r.keys, e.keys));

/** A module's FAILURE or WARNING conditions, each where it was logged (its block's id). */
const conditionsOf = (log: readonly unknown[], result: string) =>
	log
		.filter(isEntry)
		.filter((e) => e.result === result)
		.map((e) => ({ src: String(e.src), blockId: String(e.blockId) }));

const verdictOf: Readonly<Partial<Record<Class, Verdict>>> = {
	crossed: "approved",
	explained: "explained",
	unconfirmed: "unconfirmed",
};

/** One module judged against its entry (none where the expected results name none), the screen's records being this module's; `keptOf` gives each review page's kept file. */
export function judged(
	entry: Expected | undefined,
	run: ModuleRun,
	at: Provider,
	seen: readonly PageSeen[],
	keptOf: (page: ReviewPage) => string | undefined = () => undefined,
): Judged {
	const met = refusalsOf(run, at, seen);
	const problems = [...met.problems];
	const unconfirmed: string[] = [];
	if (run.status !== "FINISHED" && run.status !== "INTERRUPTED")
		problems.push(`did not finish (${run.status})`);
	if (entry === undefined) problems.push("no entry names it");
	else if (run.result !== entry.result)
		problems.push(`reported ${run.result}, its entry ${entry.result}`);
	const left = [...met.refusals];
	for (const e of entry?.refusals ?? []) {
		const same = left.filter((r) => shape(r) === shape(e));
		const hit = same.find((r) => readAs(e, r.reading)) ?? same[0];
		if (hit === undefined)
			problems.push(`its entry's refusal is unused: ${e.block}, ${e.description ?? e.status}`);
		else {
			left.splice(left.indexOf(hit), 1);
			if (!readAs(e, hit.reading))
				problems.push(
					`${e.block}: ${e.description} reads ${JSON.stringify(hit.reading)}, its entry ${e.reading}`,
				);
		}
	}
	for (const r of left) {
		if (r.reading.kind === "unconfirmed") unconfirmed.push(`${r.block}: ${r.description}`);
		else problems.push(`a refusal no entry names: ${r.block}, ${r.description ?? r.status}`);
	}
	// A condition is explained only by a key a refusal of its own block (by id) shows observed (decision 12).
	const blocks = blocksOf(run.log);
	const conditions: MetCondition[] = [];
	for (const [kind, named] of [
		["FAILURE", entry?.failures],
		["WARNING", entry?.warnings],
	] as const) {
		const ran = conditionsOf(run.log, kind);
		const wrote = named ?? [];
		for (const c of ran) {
			const e = wrote.find((w) => w.src === c.src);
			const block = blocks.get(c.blockId) ?? noBlock;
			const shown = met.refusals.flatMap((r) =>
				r.blockId === c.blockId && r.reading.kind === "observed" ? [r.reading.key] : [],
			);
			const keys = e?.keys ?? [];
			const unshown = keys.filter((key) => !shown.includes(key));
			conditions.push({ kind, ...c, block, named: e !== undefined, keys, unshown });
			if (e === undefined) problems.push(`a ${kind} no entry names: ${c.src}`);
			for (const key of unshown)
				problems.push(
					`${c.src} in ${block} is explained by ${key}, which no refusal of its block shows`,
				);
		}
		for (const w of wrote)
			if (!ran.some((c) => c.src === w.src))
				problems.push(`its entry's ${kind} is unused: ${w.src}`);
	}
	const observed = [
		...new Set(met.refusals.flatMap((r) => (r.reading.kind === "observed" ? [r.reading.key] : []))),
	].sort();
	const reading = entry?.reading;
	const pages =
		run.result === "REVIEW"
			? reviewPagesOf(run.test, run.log).filter((p) => p.state !== "released")
			: [];
	if (run.result === "REVIEW" && pages.length === 0)
		problems.push("a REVIEW with no page to stand on");
	const classed: Class =
		problems.length > 0
			? "failed"
			: unconfirmed.length > 0 || reading === "unconfirmed"
				? "unconfirmed"
				: reading === "passed" || reading === "own-condition"
					? "crossed"
					: (reading as Class);
	// One verdict for the module's pages, from its class as decided.
	const verdict = verdictOf[classed] ?? "unmatched";
	const reviews = pages.map((page) =>
		reviewed(page, verdict, `${classed}: ${reading ?? "no entry"}`, keptOf(page)),
	);
	if (reviews.some((r) => r.verdict === "unmatched") && classed !== "failed")
		problems.push("a review is unmatched");
	return {
		test: run.test,
		variant: run.variant,
		result: run.result,
		class: problems.length > 0 ? "failed" : classed,
		blocks: [...blocks].map(([id, message]) => ({ id, message })),
		refusals: met.refusals,
		conditions,
		observed,
		computed: computedOf(run, at),
		problems,
		unconfirmed,
		reviews,
	};
}

/**
 * A run judged: the screen's records each given to the one module whose visits name its key (one no
 * module's, or more than one's, fails the run), then each module; and what fails the run as a whole.
 */
export function runJudged(
	entries: readonly Expected[],
	runs: readonly ModuleRun[],
	at: Provider,
	seen: readonly PageSeen[],
	keptOf: (page: ReviewPage) => string | undefined = () => undefined,
) {
	const name = (test: string, variant: Readonly<Record<string, string>>) =>
		`${test} ${JSON.stringify(Object.entries(variant).sort(([a], [b]) => a.localeCompare(b)))}`;
	const byName = new Map(entries.map((e) => [name(e.test, e.variant), e]));
	const keys = runs.map((run) => new Set(visitsOf(run, at).keys()));
	const given: PageSeen[][] = runs.map(() => []);
	const problems: string[] = [];
	seen.forEach((s, i) => {
		const owners = keys.flatMap((k, at) => (k.has(keyOfSeen(s)) ? [at] : []));
		const [only] = owners;
		if (owners.length === 1 && only !== undefined) given[only]?.push(s);
		else if (s.kind === "refused")
			problems.push(
				`the screen's record ${i + 1} (${s.at}) is ${owners.length === 0 ? "no module's visit" : "more than one module's"}`,
			);
	});
	const modules = runs.map((run, i) =>
		judged(byName.get(name(run.test, run.variant)), run, at, given[i] ?? [], keptOf),
	);
	const ran = new Set(runs.map((r) => name(r.test, r.variant)));
	problems.unshift(
		...entries
			.filter((e) => !ran.has(name(e.test, e.variant)))
			.map((e) => `an entry no module ran: ${e.test}`),
		...modules
			.filter((m) => m.class === "failed")
			.map((m) => `${m.test} failed: ${m.problems.join("; ")}`),
	);
	return { modules, problems, passed: problems.length === 0 };
}
