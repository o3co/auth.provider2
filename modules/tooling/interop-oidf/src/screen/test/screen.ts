/**
 * The login screen as a page runs it, on the real SDK, its requests sent to the issuer: a login under
 * PAR by the client and `request_uri` alone, approved by a passkey the browser holds or denied by the
 * person, and a sign-up making that passkey. Taken from attack-harness's roles (G14 lets no package
 * share them), as the plan's interim until the SDK offers a screen for tests.
 */
import { createHash } from "node:crypto";
import { hpke } from "@mod/sdk-core-wire";
import {
	answers,
	authorization,
	firstKey,
	type Jwk,
	keyChanges,
	type ReadCreation,
	type ReadT,
	type ScreenKeys,
	screenKeys,
	signUp,
} from "@sdk/login-screen";
import type { Browser } from "./browser.ts";

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const utf8 = (text: string) => new TextEncoder().encode(text);

/** A request to the issuer, its JSON body: its status and its JSON answer, as the page sends it. */
export type Post = (
	path: string,
	body: Record<string, unknown>,
) => Promise<{ readonly status: number; readonly body: unknown }>;

/** Where a step stopped: the provider refused it (at a path, its answer), the SDK did, or the browser did. */
export type Stopped =
	| {
			readonly stopped: "provider";
			readonly at: string;
			readonly status: number;
			readonly body: unknown;
	  }
	| { readonly stopped: "sdk" | "browser"; readonly at: string; readonly error: string };

const refusedAt = (at: string, answered: { status: number; body: unknown }): Stopped => ({
	stopped: "provider",
	at,
	status: answered.status,
	body: answered.body,
});
const sdkRefused = (at: string, error: string): Stopped => ({ stopped: "sdk", at, error });

/** A browser's call, its refusal (a thrown DOMException, an unreadable attestation) a stop of its own. */
function inBrowser<T extends object | string>(at: string, call: () => T): T | Stopped {
	try {
		return call();
	} catch (error) {
		return { stopped: "browser", at, error: (error as Error)?.name ?? String(error) };
	}
}

/** Whether a step stopped, and where. */
export const stopped = (value: object | string): value is Stopped =>
	typeof value === "object" && "stopped" in value;

/** What the page pins, never from the Front: the Core's ring and its issuer. */
export interface Pins {
	readonly ring: readonly Jwk[];
	readonly issuer: string;
}

/** What the page sends the RP once T is approved: the code, and T's state, issuer and redirect URI. */
export interface Callback {
	readonly code: string;
	readonly state: string;
	readonly iss: string;
	readonly redirectUri: string;
}

/** What the page sends the RP when the person refuses: `access_denied`, and T's state, issuer and redirect URI. */
export interface Denied {
	readonly error: "access_denied";
	readonly state: string;
	readonly iss: string;
	readonly redirectUri: string;
}

/** What the page sends the RP when the Core refused the finish: the Core's word, and T's state, issuer and redirect URI. */
export interface Refused {
	readonly error: string;
	readonly state: string;
	readonly iss: string;
	readonly redirectUri: string;
}

/** An authorization the screen started: T as the SDK read it, the keys T names, and whether a sign-up is offered. */
export interface Started {
	readonly t: ReadT;
	readonly keys: ScreenKeys;
	readonly create: boolean;
}

/** The login screen, its pins read when it starts, its browser's passkeys, and the RP name it shows. */
export function loginScreen(pins: () => Pins, browser: Browser, rpName = "The RP") {
	const rpId = new URL(browser.origin).hostname;

	/**
	 * A login's start under PAR, the screen holding no JAR: the URL's `client_id` and `request_uri` sent
	 * as they came (absent where absent, for the provider to answer), under new keys; T held to them.
	 */
	const startPushed = async (
		post: Post,
		clientId: string | undefined,
		requestUri: string | undefined,
	): Promise<Started | Stopped> => {
		const sdk = pins();
		const keys = await screenKeys();
		const answered = await post("/login/start", {
			...(clientId === undefined ? {} : { clientId }),
			...(requestUri === undefined ? {} : { requestUri }),
			eEnc: keys.eEnc,
			eSigX: keys.eSig.x,
			eSigY: keys.eSig.y,
		});
		if (answered.status !== 200) return refusedAt("/login/start", answered);
		if (clientId === undefined || requestUri === undefined)
			return sdkRefused("authorization.readPushed", "no client_id or request_uri to hold T to");
		const read = answers.read("authorization", answered.body);
		if (!read) return sdkRefused("answers.read", "answer");
		const t = await authorization.readPushed(
			read.statement,
			{ clientId, requestUri },
			{ ...sdk, keys },
		);
		if ("error" in t) return sdkRefused("authorization.readPushed", t.error);
		return { t: t.t, keys, create: read.create };
	};

	/** A creation's key made, registered and possessed: the new credential's id. */
	const register = async (
		post: Post,
		creation: ReadCreation,
		keys: ScreenKeys,
	): Promise<{ readonly credential: string } | Stopped> => {
		const sdk = pins();
		const options = await firstKey.createOptions(creation, { rpName });
		if ("error" in options) return sdkRefused("firstKey.createOptions", options.error);
		const made = inBrowser("create", () => browser.create(options.options));
		if (stopped(made)) return made;
		const seq = 1;
		const signed = await firstKey.continuation(creation, seq, made.json, keys);
		if ("error" in signed) return sdkRefused("firstKey.continuation", signed.error);
		const registered = await post("/continue", {
			statement: creation.compact,
			stage: "register",
			seq: String(seq),
			body: made.json,
			sig: signed.signature,
		});
		if (registered.status !== 200) return refusedAt("/continue register", registered);
		const possessionJws = answers.read("statement", registered.body);
		if (possessionJws === undefined) return sdkRefused("answers.read", "answer");
		const possession = await firstKey.readPossession(
			possessionJws,
			creation,
			{ id: made.id, spki: made.spki, alg: made.alg },
			{ ...sdk, keys },
		);
		if ("error" in possession) return sdkRefused("firstKey.readPossession", possession.error);
		const getOptions = await firstKey.assertionOptions(possession.possession);
		if ("error" in getOptions) return sdkRefused("firstKey.assertionOptions", getOptions.error);
		const assertion = inBrowser("get", () => browser.get(getOptions.options));
		if (stopped(assertion)) return assertion;
		const finished = await post("/key/finish", { statement: possessionJws, assertion });
		if (finished.status !== 200) return refusedAt("/key/finish", finished);
		const sealed = answers.read("sealed", finished.body);
		if (sealed === undefined) return sdkRefused("answers.read", "answer");
		const change = await keyChanges.read(
			{ add: possession.possession, assertion: utf8(assertion) },
			sealed,
			{ ...sdk, keys, checks: { level: "L0" } },
		);
		if ("error" in change) return sdkRefused("keyChanges.read", change.error);
		if (!("change" in change)) return sdkRefused("keyChanges.read", "change");
		return { credential: made.id };
	};

	/** F1: T's sign-up, its creation, the new key made, registered and possessed; the credential's id. */
	const signUpWith = async (
		post: Post,
		started: Started,
	): Promise<{ readonly credential: string } | Stopped> => {
		const sdk = pins();
		const { t, keys } = started;
		const asked = await signUp.continuation(t, keys);
		if ("error" in asked) return sdkRefused("signUp.continuation", asked.error);
		const signedUp = await post("/continue", {
			statement: t.compact,
			stage: asked.stage,
			seq: String(asked.seq),
			body: asked.body,
			sig: asked.sig,
		});
		if (signedUp.status !== 200) return refusedAt("/continue sign-up", signedUp);
		const creationJws = answers.read("statement", signedUp.body);
		if (creationJws === undefined) return sdkRefused("answers.read", "answer");
		const creation = await signUp.readCreation(creationJws, t, { ...sdk, keys });
		if ("error" in creation) return sdkRefused("signUp.readCreation", creation.error);
		return register(post, creation.creation, keys);
	};

	/** T approved by a passkey the browser holds, the completion opened: what the page sends the RP. */
	const approve = async (post: Post, started: Started): Promise<Callback | Stopped> => {
		const sdk = pins();
		const { t, keys } = started;
		const options = await authorization.assertionOptions(t, { rpId });
		if ("error" in options) return sdkRefused("authorization.assertionOptions", options.error);
		const assertion = inBrowser("get", () => browser.get(options.options));
		if (stopped(assertion)) return assertion;
		const finished = await post("/login/finish", { statement: t.compact, assertion });
		if (finished.status !== 200) return refusedAt("/login/finish", finished);
		const sealed = answers.read("sealed", finished.body);
		if (sealed === undefined) return sdkRefused("answers.read", "answer");
		const done = await authorization.finish(t, sealed, {
			...sdk,
			keys,
			aad: utf8(hpke.completionAad("authorization", sha256(t.compact))),
			assertion: utf8(assertion),
			level: "L0",
		});
		if ("error" in done) return sdkRefused("authorization.finish", done.error);
		const { state, redirect_uri } = t.statement.approval;
		return { code: done.code, state, iss: t.statement.iss, redirectUri: redirect_uri };
	};

	/** The person refuses T: the denial the page sends the RP, every value T's; nothing is sent to the Core. */
	const deny = (started: Started): Denied | Stopped => {
		const denied = authorization.denial(started.t);
		if ("error" in denied) return sdkRefused("authorization.denial", denied.error);
		return { ...denied.fields, redirectUri: denied.redirectUri };
	};

	/**
	 * The Core's refusal of the finish (`approve` stopped at it), carried to the RP as a denial is (OIDC
	 * Core §3.1.2.6): the word read from the Core's answer, every other value T's; a stop where none is carried.
	 */
	const carry = (started: Started, stop: Stopped): Refused | Stopped => {
		const body = stop.stopped === "provider" && stop.at === "/login/finish" ? stop.body : undefined;
		const word = (body as { readonly error?: unknown } | undefined)?.error;
		if (typeof word !== "string")
			return sdkRefused("authorization.refusal", "no refusal of the Core");
		const carried = authorization.refusal(started.t, word);
		if ("error" in carried) return sdkRefused("authorization.refusal", carried.error);
		return { ...carried.fields, redirectUri: carried.redirectUri };
	};

	return { startPushed, signUp: signUpWith, approve, deny, carry };
}

export type LoginScreen = ReturnType<typeof loginScreen>;
