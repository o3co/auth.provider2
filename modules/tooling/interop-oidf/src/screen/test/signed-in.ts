/**
 * A person signed up at a scene, its screen's pages before it, and a relying party registered: what a
 * test of a later step (the resource, the run) starts from, the setup once. A login through the pages
 * ends with the RP holding its tokens.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Jwk } from "@sdk/login-screen";
import { stopAll } from "../../lifecycle/lifecycle.ts";
import {
	type Provider,
	type RelyingParty,
	relyingParty,
	type Started,
	send,
} from "../../rp/test/rp.ts";
import { type Answered, ask, atIssuer } from "../../scene/test/ask.ts";
import { type Scene, startScene } from "../../scene/test/scene.ts";
import { browser } from "./browser.ts";
import { type Pages, startPages } from "./page.ts";
import { type LoginScreen, loginScreen, type Pins, type Post, stopped } from "./screen.ts";

/** The tokens a login ended with, and the RP's session they are bound to. */
export interface LoggedIn {
	readonly session: Started;
	readonly tokens: Readonly<Record<string, unknown>>;
}

/** The scene, its pages and its RP, a person signed up; a login to tokens; and the stop of all of it. */
export interface SignedIn {
	readonly scene: Scene;
	readonly pages: Pages;
	readonly rp: RelyingParty;
	/** A request at the issuer, as the RP sends it. */
	readonly at: (path: string, init: Parameters<typeof ask>[2]) => Promise<Answered>;
	/** A login through the screen role (no page between: the page's own is `page.ts`'s), its code exchanged. */
	login(): Promise<LoggedIn>;
	stop(): Promise<void>;
}

/** Starts it all; a start that fails stops what it started. */
export async function signedIn(options: {
	readonly clientId: string;
	readonly redirectUri: string;
}): Promise<SignedIn> {
	const dir = await mkdtemp(join(tmpdir(), "interop-oidf-signed-in-"));
	let scene: Scene | undefined;
	let pages: Pages | undefined;
	let role: LoginScreen | undefined;
	const issuer = (): Scene => {
		if (scene === undefined) throw new Error("the scene did not start");
		return scene;
	};
	const provider = (): Provider => {
		const { issuer: origin } = issuer();
		return { issuer: origin, parUrl: `${origin}/oauth/par`, tokenUrl: `${origin}/oauth/token` };
	};
	const rp = relyingParty(options.clientId, options.redirectUri, provider);
	const at = (path: string, init: Parameters<typeof ask>[2]) => ask(atIssuer(issuer()), path, init);
	const post: Post = async (path, body) => {
		const answer = await at(path, { method: "POST", json: body });
		return { status: answer.status, body: answer.json };
	};
	/** Every part stopped though one fails (the scene first, the directory last), the failures told together. */
	const stop = async () => {
		const problems = await stopAll([
			() => rm(dir, { recursive: true, force: true }),
			async () => pages?.stop(),
			async () => scene?.stop(),
		]);
		if (problems.length > 0) throw new AggregateError(problems, "signedIn did not stop");
	};
	const screen = () => {
		if (role === undefined) throw new Error("no screen");
		return role;
	};
	/** A JAR pushed, started on the screen: the RP's session, and T. */
	const begun = async () => {
		const session = rp.authorization();
		const { answer } = await send(at, "/oauth/par", () => rp.par(session));
		if (answer.status !== 201) throw new Error(`a push: ${answer.status} ${answer.text}`);
		const started = await screen().startPushed(post, rp.clientId, String(answer.json.request_uri));
		if (stopped(started)) throw new Error(`a start: ${JSON.stringify(started)}`);
		return { session, started };
	};
	try {
		pages = await startPages({
			host: "localhost",
			listen: "127.0.0.1",
			dir,
			screen,
			post: () => post,
			carrying: () => "form_post",
		});
		scene = await startScene({
			host: "localhost",
			listen: "127.0.0.1",
			screen: pages.origin,
			clients: [rp.registered()],
		});
		const coreKeys = (await at("/core-keys.json", {})).json.keys as readonly (Jwk & {
			readonly use?: string;
		})[];
		const pins: Pins = { ring: coreKeys.filter((key) => key.use !== "enc"), issuer: scene.issuer };
		role = loginScreen(() => pins, browser(pages.origin));
		const first = await begun();
		const key = await screen().signUp(post, first.started);
		if (stopped(key)) throw new Error(`the sign-up: ${JSON.stringify(key)}`);
		return {
			scene,
			pages,
			rp,
			at,
			login: async () => {
				const { session, started } = await begun();
				const callback = await screen().approve(post, started);
				if (stopped(callback)) throw new Error(`an approval: ${JSON.stringify(callback)}`);
				const { answer } = await send(at, "/oauth/token", (nonce) =>
					rp.token(session, callback.code, nonce),
				);
				if (answer.status !== 200)
					throw new Error(`a code exchange: ${answer.status} ${answer.text}`);
				return { session, tokens: answer.json };
			},
			stop,
		};
	} catch (error) {
		// A stop that fails too is told with the start's own failure, never in its place.
		await stop().catch((stopping: unknown) => {
			throw new AggregateError([error, stopping], "signedIn did not start, nor stop");
		});
		throw error;
	}
}
