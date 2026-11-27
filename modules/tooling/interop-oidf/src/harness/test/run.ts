import { existsSync, lstatSync, readdirSync, readlinkSync, realpathSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import type { Jwk } from "@sdk/login-screen";
import { ledger } from "../../deviations/deviations.ts";
import { expectedFor } from "../../expected/expected.ts";
import { cleared, planDirs } from "../../lifecycle/lifecycle.ts";
import { reportOf } from "../../report/test/report.ts";
import { startResource } from "../../resource/test/resource.ts";
import { runJudged } from "../../results/test/results.ts";
import { keptPages, type ReviewPage, reviewPagesOf } from "../../review/review.ts";
import { type Provider as RpProvider, relyingParty, send } from "../../rp/test/rp.ts";
import { type Asking, type At, ask } from "../../scene/test/ask.ts";
import { differencesOf } from "../../scene/test/differences.ts";
import { type Scene, startScene } from "../../scene/test/scene.ts";
import { browser } from "../../screen/test/browser.ts";
import { startPages } from "../../screen/test/page.ts";
import { type LoginScreen, loginScreen, type Post, stopped } from "../../screen/test/screen.ts";
import { hostForSuite, startSuite, suitePin } from "../../suite/suite.ts";
import { clientOf, planA, planConfig, variantA } from "./config.ts";
import { runModules, timingA } from "./modules.ts";
import { startRedis } from "./redis.ts";
import { type Held, stoppedWhenEnded } from "./stops.ts";

/** PAR's JAR lifetime in run A, which sets none: par's default (its `reference.conf`). */
export const parJarMaxLifetimeA = 90;
/** How long run A may take before it starts no module more: past every module's time but one. */
export const runAms = 9 * 60 * 60_000;

/** A path as written to: its nearest existing directory's real path (links followed), the rest after. */
function realOf(path: string): string {
	const absolute = resolve(path);
	const parent = dirname(absolute);
	if (existsSync(absolute)) return realpathSync(absolute);
	// A link to nothing yet is followed to where it points: it is written there.
	const link = lstatSync(absolute, { throwIfNoEntry: false });
	if (link?.isSymbolicLink()) return realOf(resolve(parent, readlinkSync(absolute)));
	return parent === absolute ? absolute : join(realOf(parent), basename(absolute));
}
/**
 * Why `out` may not hold a record, if it may not: the record holds the run's client keys (the suite's
 * info and log carry its configuration), so it is never in a git work tree, links followed, nor a
 * directory holding a run's record already.
 */
export function outProblem(out: string): string | undefined {
	// Where it writes, links followed: the record's own directory, which may itself be a link.
	for (let dir = realOf(join(out, "a")); ; dir = dirname(dir)) {
		if (existsSync(join(dir, ".git"))) return `${out} is in the git work tree at ${dir}`;
		if (dirname(dir) === dir) break;
	}
	const record = join(out, "a");
	if (existsSync(record) && readdirSync(record).length > 0)
		return `${record} holds a record already`;
	return undefined;
}

/** A recorded run's outcome: whether it passed, and where its report is. */
export interface Ran {
	readonly passed: boolean;
	readonly report: string;
}

/**
 * Run A, recorded in `out`, never in the repository: the expected results read first, then the suite
 * at its pin against the scene on Redis, every module of the plan in turn, judged and reported.
 * Every part started is stopped however the run ends, its work directory then removed, and the
 * report is written first once judged, each other record tried after it.
 */
export async function runA(
	out: string,
	signal: AbortSignal = AbortSignal.timeout(runAms),
): Promise<Ran> {
	const refused = outProblem(out);
	if (refused !== undefined) throw new Error(refused);
	const rows = ledger();
	const entries = expectedFor(
		"a",
		rows.map((d) => d.key),
	);
	const { work, artifacts } = await planDirs("a", out);
	let scene: Scene | undefined;
	const written = (name: string, text: string) => writeFile(join(artifacts, name), text);
	const json = (name: string, value: unknown) =>
		written(name, `${JSON.stringify(value, null, 2)}\n`);
	const recorded = async (held: Held): Promise<Ran> => {
		await mkdir(join(artifacts, "modules"), { recursive: true });
		const host = await hostForSuite();
		const alias = "nextgen-a";
		const clients = [clientOf("oidf-client-1", alias), clientOf("oidf-client-2", alias)] as const;
		let role: LoginScreen | undefined;
		const ready = <T>(value: T | undefined, what: string): T => {
			if (value === undefined) throw new Error(`no ${what} yet`);
			return value;
		};
		// The harness's own calls reach the suite's name for this machine at its listening address.
		const issuerAt = (): At => {
			const { issuer, certificate } = ready(scene, "scene");
			return { origin: issuer, certificate, address: host.listen };
		};
		const at = (path: string, init: Asking = {}) => ask(issuerAt(), path, init);
		const post: Post = async (path, body) => {
			const answer = await at(path, { method: "POST", json: body });
			return { status: answer.status, body: answer.json };
		};
		let endpoints: { readonly par: string; readonly token: string } | undefined;
		const rpProvider = (): RpProvider => {
			const { par, token } = ready(endpoints, "discovery");
			return { issuer: ready(scene, "scene").issuer, parUrl: par, tokenUrl: token };
		};
		const pathOf = (url: string) => new URL(url).pathname;
		const rp = relyingParty("rp-signup", "https://rp.example.invalid/cb", rpProvider);

		const pages = await startPages({
			host: host.name,
			listen: host.listen,
			dir: join(work, "pages"),
			screen: () => ready(role, "screen"),
			post: () => post,
			carrying: () => "form_post",
		});
		held(() => pages.stop());
		const redis = await startRedis();
		held(() => redis.stop());
		const spec = {
			host: host.name,
			listen: host.listen,
			screen: pages.origin,
			clients: [clients[0].registered, clients[1].registered, rp.registered()],
			redis: { url: redis.url },
		};
		scene = await startScene(spec);
		const started = scene;
		held(() => started.stop());
		// The endpoints as the provider publishes them, one source for the user's sign-up and for results.
		const discovery = (await at("/.well-known/openid-configuration")).json;
		const named = (key: string) => {
			const url = discovery[key];
			if (typeof url !== "string") throw new Error(`the discovery document names no ${key}`);
			return url;
		};
		endpoints = {
			par: named("pushed_authorization_request_endpoint"),
			token: named("token_endpoint"),
		};
		const { par, token } = endpoints;

		// The user signs up before the suite starts: every flow module's login is theirs.
		const keys = (await at("/core-keys.json")).json.keys as readonly (Jwk & { use?: string })[];
		const pins = { ring: keys.filter((k) => k.use !== "enc"), issuer: started.issuer };
		role = loginScreen(() => pins, browser(pages.origin));
		const authorization = rp.authorization();
		const pushed = await send(at, pathOf(par), () => rp.par(authorization));
		const begun = await role.startPushed(post, rp.clientId, String(pushed.answer.json.request_uri));
		if (stopped(begun)) throw new Error(`the sign-up did not start: ${JSON.stringify(begun)}`);
		const signed = await role.signUp(post, begun);
		if (stopped(signed)) throw new Error(`the sign-up stopped: ${JSON.stringify(signed)}`);

		const resource = await startResource({
			host: host.name,
			listen: host.listen,
			dir: join(work, "resource"),
			issuer: () => started.issuer,
			audience: () => started.issuer,
			jwks: async () => (await at("/jwks.json")).json.keys as Readonly<Record<string, unknown>>[],
		});
		held(() => resource.stop());
		const pin = await suitePin();
		const tls = await selfSigned("localhost.emobix.co.uk", join(work, "suite-tls"));
		const suite = await startSuite(
			pin,
			join(work, "suite"),
			host,
			join(artifacts, "suite.log"),
			tls,
			{
				signal,
			},
		);
		held(() => suite.stop());

		const reached = { alias, issuer: started.issuer, screen: pages.origin, resource: resource.url };
		const variant = encodeURIComponent(JSON.stringify(variantA));
		const plan = await suite.call(
			"POST",
			`api/plan?planName=${planA}&variant=${variant}`,
			planConfig(reached, clients),
		);
		await json("plan.json", plan);
		const planBody = plan.body as { id?: string; modules?: { testModule: string }[] };
		if (planBody.id === undefined || planBody.modules === undefined)
			throw new Error(`the suite made no plan: ${plan.status}`);
		const runs = await runModules(
			suite,
			{ id: planBody.id, variant: variantA, tests: planBody.modules.map((m) => m.testModule) },
			timingA,
			async (test, info, log) => {
				await json(`modules/${test}.info.json`, info);
				await json(`modules/${test}.log.json`, log);
			},
			signal,
		);

		// A page is its whole entry: two alike are one page, kept once.
		const kept = new Map<string, string | undefined>();
		for (const r of runs.filter((r) => r.result === "REVIEW")) {
			const pagesOf = reviewPagesOf(r.test, r.log);
			const files = await keptPages(pagesOf, join(artifacts, "reviews"));
			for (const [i, p] of pagesOf.entries()) kept.set(JSON.stringify(p), files[i]);
		}
		const provider = {
			par,
			token,
			resource: resource.url,
			screen: pages.origin,
			parJarMaxLifetimeS: parJarMaxLifetimeA,
		};
		const keptOf = (p: ReviewPage) => kept.get(JSON.stringify(p));
		const judged = runJudged(entries, runs, provider, pages.seen(), keptOf);
		const report = join(artifacts, "report.md");
		const differences = differencesOf(spec);
		const pinned = `${pin.tag} ${pin.commit}`;
		const text = reportOf({
			run: "A",
			plan: planA,
			pin: pinned,
			differences,
			judged,
			ledger: rows,
		});
		const records = [
			() => writeFile(report, text),
			() => json("judged.json", judged),
			() => json("pages-seen.json", pages.seen()),
			() => json("resource-refused.json", resource.refused()),
		];
		const failed: unknown[] = [];
		for (const write of records) await write().catch((e: unknown) => failed.push(e));
		if (failed.length > 0)
			throw new AggregateError(failed, "run A was judged, and not every record was written");
		return { passed: judged.passed, report };
	};
	const { ran, after, problems } = await stoppedWhenEnded(signal, recorded);
	// Each app's output, whole once stopped: the Core's boot warnings (the store's statements) among it.
	const unwritten: unknown[] = [];
	for (const { name, out: text } of scene?.outputs() ?? [])
		await written(`${name.replace(/[^A-Za-z0-9.-]/g, "-")}.out.txt`, text).catch((e: unknown) =>
			unwritten.push(e),
		);
	// A failure of the body's own after the signal keeps the work only where it is a stop's that failed
	// (`SuiteStopFailed`, as `cleared` reads it): anything else of it is told beside the run's.
	const bodyFailed = after !== undefined && "failed" in after ? [after.failed] : [];
	await cleared(work, bodyFailed[0] ?? ("failed" in ran ? ran.failed : undefined), problems);
	// A work directory kept holds what stops the part that failed, the TLS keys among it: named here.
	const kept = existsSync(work) ? [new Error(`the work directory is kept: ${work}`)] : [];
	const told = [...problems, ...unwritten, ...kept];
	// Ended by its signal, the run fails though its body went on to write a report: named, for reading.
	const reported =
		after !== undefined && "value" in after
			? [new Error(`its body wrote a report all the same: ${after.value.report}`)]
			: [];
	if ("failed" in ran)
		throw told.length + reported.length + bodyFailed.length === 0
			? ran.failed
			: new AggregateError(
					[ran.failed, ...reported, ...bodyFailed, ...told],
					told.length === 0 ? "run A failed" : "run A failed, and did not stop or record whole",
				);
	if (told.length > 0) throw new AggregateError(told, "run A did not stop or record whole");
	return ran.value;
}
