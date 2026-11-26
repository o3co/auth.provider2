import { createHash } from "node:crypto";
import { hpke } from "@mod/sdk-core-wire";
import {
	answers,
	authorization,
	firstKey,
	type Jwk,
	keyChanges,
	type ReadT,
	type ScreenKeys,
	screenKeys,
	signUp,
} from "@sdk/login-screen";
import type { Answered, BadFront } from "../../src/contract.ts";
import type { Browser } from "./browser.ts";

/**
 * Where a step stopped, and at what (`at`: the path posted, or the SDK's or browser's call): the Core
 * refused it (its reply on the wire a refusal, or a rejection of the frame), the Front did (nothing
 * sent, or the Core's reply rewritten into a refusal), the SDK did (its error), or the browser did
 * (its authenticator's refusal).
 */
export type Stopped =
	| { readonly stopped: "core" | "front"; readonly at: string; readonly answered: Answered }
	| { readonly stopped: "sdk" | "browser"; readonly at: string; readonly error: string };

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const utf8 = (text: string) => new TextEncoder().encode(text);

/** A request's refusal: the Core's where its reply on the wire was one, else the Front's. */
const refusedAt = (at: string, answered: Answered): Stopped => ({
	stopped:
		answered.wire?.outcome === "refused" || answered.wire?.outcome === "rejected"
			? "core"
			: "front",
	at,
	answered,
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

/** What the page pins, never from the Front: the Core's ring, its issuer. */
export interface Pins {
	readonly ring: readonly Jwk[];
	readonly issuer: string;
}

/** What the page POSTs to the RP's redirect URI once T is approved: the code, and T's state. */
export interface Callback {
	readonly code: string;
	readonly state: string;
	readonly redirectUri: string;
}

/** An authorization the screen started: T as the SDK read it, the keys T names, and whether F1 is offered. */
export interface Started {
	readonly t: ReadT;
	readonly keys: ScreenKeys;
	readonly create: boolean;
}

/**
 * The login screen as a page runs it: the real SDK's steps, the requests sent through the Front, the
 * passkeys made and used in the browser. Each step answers its value, or where it stopped. The RP's
 * form_post endpoint (R12) is not played: the callback goes to the RP, never through the Front.
 */
export function loginScreen(
	pins: Pins,
	browser: Browser,
	page: { readonly rpName?: string; readonly rpId?: string } = {},
) {
	const rpName = page.rpName ?? "The RP";
	// WebAuthn's RP id: the page's host, unless the page asks for a domain above it.
	const rpId = page.rpId ?? new URL(browser.origin).hostname;
	const sdk = { ring: pins.ring, issuer: pins.issuer };

	/**
	 * ② The login's start, for the JAR the RP gave, sent as it is or by the request_uri PAR gave for it:
	 * T read against the JAR the screen holds.
	 */
	const start = async (
		front: BadFront,
		clientId: string,
		jar: string,
		requestUri?: string,
	): Promise<Started | Stopped> => {
		const keys = await screenKeys();
		const answered = await front.post({
			path: "/login/start",
			body: {
				clientId,
				...(requestUri === undefined ? { request: jar } : { requestUri }),
				eEnc: keys.eEnc,
				eSigX: keys.eSig.x,
				eSigY: keys.eSig.y,
			},
		});
		if (answered.status !== 200) return refusedAt("/login/start", answered);
		const read = answers.read("authorization", answered.body);
		if (!read) return sdkRefused("answers.read", "answer");
		const t = await authorization.read(read.statement, jar, { ...sdk, keys });
		if ("error" in t) return sdkRefused("authorization.read", t.error);
		return { t: t.t, keys, create: read.create };
	};

	/** F1: T's sign-up, its creation, the new key made, registered and possessed; the credential's id. */
	const signUpWith = async (
		front: BadFront,
		started: Started,
	): Promise<{ readonly credential: string } | Stopped> => {
		const { t, keys } = started;
		const asked = await signUp.continuation(t, keys);
		if ("error" in asked) return sdkRefused("signUp.continuation", asked.error);
		const signedUp = await front.post({
			path: "/continue",
			body: {
				statement: t.compact,
				stage: asked.stage,
				seq: String(asked.seq),
				body: asked.body,
				sig: asked.sig,
			},
		});
		if (signedUp.status !== 200) return refusedAt("/continue sign-up", signedUp);
		const creationJws = answers.read("statement", signedUp.body);
		if (creationJws === undefined) return sdkRefused("answers.read", "answer");
		const creation = await signUp.readCreation(creationJws, t, { ...sdk, keys });
		if ("error" in creation) return sdkRefused("signUp.readCreation", creation.error);
		const options = await firstKey.createOptions(creation.creation, { rpName });
		if ("error" in options) return sdkRefused("firstKey.createOptions", options.error);
		const made = inBrowser("create", () => browser.create(options.options));
		if (stopped(made)) return made;
		const seq = 1;
		const signed = await firstKey.continuation(creation.creation, seq, made.json, keys);
		if ("error" in signed) return sdkRefused("firstKey.continuation", signed.error);
		const registered = await front.post({
			path: "/continue",
			body: {
				statement: creationJws,
				stage: "register",
				seq: String(seq),
				body: made.json,
				sig: signed.signature,
			},
		});
		if (registered.status !== 200) return refusedAt("/continue register", registered);
		const possessionJws = answers.read("statement", registered.body);
		if (possessionJws === undefined) return sdkRefused("answers.read", "answer");
		const possession = await firstKey.readPossession(
			possessionJws,
			creation.creation,
			{ id: made.id, spki: made.spki, alg: made.alg },
			{ ...sdk, keys },
		);
		if ("error" in possession) return sdkRefused("firstKey.readPossession", possession.error);
		const getOptions = await firstKey.assertionOptions(possession.possession);
		if ("error" in getOptions) return sdkRefused("firstKey.assertionOptions", getOptions.error);
		const assertion = inBrowser("get", () => browser.get(getOptions.options));
		if (stopped(assertion)) return assertion;
		const finished = await front.post({
			path: "/key/finish",
			body: { statement: possessionJws, assertion },
		});
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

	/**
	 * ③〜⑤ T approved by a passkey the browser holds, the completion opened: the callback the page POSTs
	 * to the RP (form_post), not through the Front: the code, and T's state and redirect URI.
	 */
	const approve = async (
		front: BadFront,
		started: Started,
		credentials?: readonly string[],
	): Promise<Callback | Stopped> => {
		const { t, keys } = started;
		const options = await authorization.assertionOptions(t, {
			rpId,
			...(credentials !== undefined && { credentials }),
		});
		if ("error" in options) return sdkRefused("authorization.assertionOptions", options.error);
		const assertion = inBrowser("get", () => browser.get(options.options));
		if (stopped(assertion)) return assertion;
		const finished = await front.post({
			path: "/login/finish",
			body: { statement: t.compact, assertion },
		});
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
		return { code: done.code, state, redirectUri: redirect_uri };
	};

	return { start, signUp: signUpWith, approve };
}

export type LoginScreen = ReturnType<typeof loginScreen>;
