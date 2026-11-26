import { createHash } from "node:crypto";
import { hpke } from "@mod/sdk-core-wire";
import {
	answers,
	authorization,
	type Continued,
	challengeOf,
	firstKey,
	type Jwk,
	type KeptDelete,
	keyChanges,
	type Mail,
	type ManagementPurpose,
	management,
	type ReadCreation,
	type ReadManage,
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

/** What the page pins, never from the Front: the Core's ring, its issuer, its sealing key (raw P-256). */
export interface Pins {
	readonly ring: readonly Jwk[];
	readonly issuer: string;
	readonly sealingKey?: Uint8Array;
}

/** A management approval taken: its statement as read, the keys it names, and what its completion gave. */
export interface Approved {
	readonly manage: ReadManage;
	readonly keys: ScreenKeys;
	readonly done: { readonly creation: ReadCreation } | { readonly keys: readonly unknown[] };
}

/** A delete's answer: the change the Core made, or the keys kept and why it did not take. */
export type Deleted = { readonly deleted: true } | { readonly kept: KeptDelete };

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

	/**
	 * A creation's key made, registered and possessed (the first key's steps, on any path): `create()`,
	 * the register continuation, the possession read, the new key's `get()` and its finish, the change
	 * read at L0; the new credential's id.
	 */
	const register = async (
		front: BadFront,
		creation: ReadCreation,
		keys: ScreenKeys,
		device: Browser = browser,
	): Promise<{ readonly credential: string } | Stopped> => {
		const creationJws = creation.compact;
		const options = await firstKey.createOptions(creation, { rpName });
		if ("error" in options) return sdkRefused("firstKey.createOptions", options.error);
		const made = inBrowser("create", () => device.create(options.options));
		if (stopped(made)) return made;
		const seq = 1;
		const signed = await firstKey.continuation(creation, seq, made.json, keys);
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
			creation,
			{ id: made.id, spki: made.spki, alg: made.alg },
			{ ...sdk, keys },
		);
		if ("error" in possession) return sdkRefused("firstKey.readPossession", possession.error);
		const getOptions = await firstKey.assertionOptions(possession.possession);
		if ("error" in getOptions) return sdkRefused("firstKey.assertionOptions", getOptions.error);
		const assertion = inBrowser("get", () => device.get(getOptions.options));
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
		return register(front, creation.creation, keys);
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

	/**
	 * A management approval (passkey-add or passkey-manage) by a passkey the browser holds (`credential`,
	 * else any it holds for the RP): its statement read, asserted and finished, the completion opened.
	 */
	const approveManagement = async (
		front: BadFront,
		purpose: ManagementPurpose,
		credential?: string,
		/** The keys a page holds already; fresh ones unless given. */
		given?: ScreenKeys,
	): Promise<Approved | Stopped> => {
		const keys = given ?? (await screenKeys());
		const started = await front.post({
			path: "/approval/start",
			body: { purpose, eEnc: keys.eEnc, eSigX: keys.eSig.x, eSigY: keys.eSig.y },
		});
		if (started.status !== 200) return refusedAt("/approval/start", started);
		const jws = answers.read("statement", started.body);
		if (jws === undefined) return sdkRefused("answers.read", "answer");
		const read = await management.read(jws, { ...sdk, keys, purpose });
		if ("error" in read) return sdkRefused("management.read", read.error);
		const challenge = await challengeOf(jws, "get");
		const assertion = inBrowser("get", () =>
			browser.get({
				challenge,
				rpId,
				allowCredentials:
					credential === undefined
						? []
						: [{ type: "public-key", id: Buffer.from(credential, "base64url") }],
				userVerification: "required",
			}),
		);
		if (stopped(assertion)) return assertion;
		const finished = await front.post({
			path: "/approval/finish",
			body: { statement: jws, assertion },
		});
		if (finished.status !== 200) return refusedAt("/approval/finish", finished);
		const sealed = answers.read("sealed", finished.body);
		if (sealed === undefined) return sdkRefused("answers.read", "answer");
		const done = await management.finish(read.manage, sealed, {
			...sdk,
			keys,
			assertion: utf8(assertion),
		});
		if ("error" in done) return sdkRefused("management.finish", done.error);
		return { manage: read.manage, keys, done };
	};

	/**
	 * passkey-add: a new key made on `device` (a person's other authenticator: one excludes the
	 * credentials it holds), approved by one this browser holds; the new credential's id.
	 */
	const addKey = async (
		front: BadFront,
		approver: string,
		device: Browser,
	): Promise<{ readonly credential: string } | Stopped> => {
		const approved = await approveManagement(front, "passkey-add", approver);
		if (stopped(approved)) return approved;
		if (!("creation" in approved.done)) return sdkRefused("management.finish", "creation");
		return register(front, approved.done.creation, approved.keys, device);
	};

	/** passkey-manage: a key deleted, approved by one the browser holds; the change, or what was kept. */
	const deleteKey = async (
		front: BadFront,
		approver: string,
		target: string,
		given?: ScreenKeys,
	): Promise<Deleted | Stopped> => {
		if (pins.sealingKey === undefined) throw new Error("a delete seals to the Core's key: pin it");
		const approved = await approveManagement(front, "passkey-manage", approver, given);
		if (stopped(approved)) return approved;
		const { manage, keys } = approved;
		const made = await management.continuation(
			manage,
			"delete",
			1,
			{ credential_id: target },
			{
				keys,
				sealingKey: pins.sealingKey,
			},
		);
		if ("error" in made) return sdkRefused("management.continuation", made.error);
		const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
		const answered = await front.post({
			path: "/continue",
			body: {
				statement: manage.compact,
				stage: "delete",
				seq: "1",
				body: "",
				sig: "",
				enc: b64u(made.sealed.enc),
				ct: b64u(made.sealed.ct),
			},
		});
		if (answered.status !== 200) return refusedAt("/continue delete", answered);
		const sealed = answers.read("sealed", answered.body);
		if (sealed === undefined) return sdkRefused("answers.read", "answer");
		const change = await keyChanges.read({ delete: made.sent as Continued }, sealed, {
			...sdk,
			keys,
			checks: { level: "L0" },
		});
		if ("error" in change) return sdkRefused("keyChanges.read", change.error);
		if ("kept" in change) return { kept: change.kept };
		if ("change" in change) return { deleted: true };
		return sdkRefused("keyChanges.read", "retry");
	};

	const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
	/** What the first key's sealing needs of the pins: the Core's sealing key, required. */
	const firstKeyOptions = (keys: ScreenKeys) => {
		if (pins.sealingKey === undefined)
			throw new Error("the first key seals to the Core's key: pin it");
		return { ...sdk, keys, sealingKey: pins.sealingKey };
	};
	/** A first key's nonce of a stage, its keys named alongside as the sealed request's are. */
	const nonceOf = async (front: BadFront, stage: "start" | "mail"): Promise<string | Stopped> => {
		const answered = await front.post({ path: "/first-key/nonce", body: { stage } });
		if (answered.status !== 200) return refusedAt("/first-key/nonce", answered);
		return answers.read("nonce", answered.body) ?? sdkRefused("answers.read", "answer");
	};
	/** A sealed request's body: its nonce, the screen's keys, and the sealed request. */
	const sealedBody = (
		nonce: string,
		keys: ScreenKeys,
		sealed: { enc: Uint8Array; ct: Uint8Array },
	) => ({
		nonce,
		eEnc: keys.eEnc,
		eSigX: keys.eSig.x,
		eSigY: keys.eSig.y,
		enc: b64url(sealed.enc),
		ct: b64url(sealed.ct),
	});

	/** The first key's start (§3.13's step 1): the identifier sealed to the Core, its code opened; the keys it was sealed under. */
	const firstKeyStart = async (
		front: BadFront,
		identifier: string,
	): Promise<{ readonly code: string; readonly keys: ScreenKeys } | Stopped> => {
		const keys = await screenKeys();
		const nonce = await nonceOf(front, "start");
		if (stopped(nonce)) return nonce;
		const made = await firstKey.start({ identifier }, nonce, firstKeyOptions(keys));
		if ("error" in made) return sdkRefused("firstKey.start", made.error);
		const answered = await front.post({
			path: "/first-key/start",
			body: sealedBody(nonce, keys, made.sealed),
		});
		if (answered.status !== 200) return refusedAt("/first-key/start", answered);
		const sealed = answers.read("sealed", answered.body);
		if (sealed === undefined) return sdkRefused("answers.read", "answer");
		const opened = await firstKey.openCode(sealed, nonce, { keys });
		if ("error" in opened) return sdkRefused("firstKey.openCode", opened.error);
		return { code: opened.code, keys };
	};

	/**
	 * The mail's side, on the page the link opened (keys of its own unless given): the token, the
	 * identifier and the start's code sealed to the Core, the creation it answers read against them.
	 */
	const firstKeyMail = async (
		front: BadFront,
		plain: { readonly token: string; readonly identifier: string; readonly code: string },
		given?: ScreenKeys,
	): Promise<
		{ readonly creation: ReadCreation; readonly mail: Mail; readonly keys: ScreenKeys } | Stopped
	> => {
		const keys = given ?? (await screenKeys());
		const nonce = await nonceOf(front, "mail");
		if (stopped(nonce)) return nonce;
		const made = await firstKey.mail(plain, nonce, firstKeyOptions(keys));
		if ("error" in made) return sdkRefused("firstKey.mail", made.error);
		const answered = await front.post({
			path: "/first-key/mail",
			body: sealedBody(nonce, keys, made.mail.sealed),
		});
		if (answered.status !== 200) return refusedAt("/first-key/mail", answered);
		const compact = answers.read("statement", answered.body);
		if (compact === undefined) return sdkRefused("answers.read", "answer");
		const read = await firstKey.readCreation(compact, made.mail, firstKeyOptions(keys));
		if ("error" in read) return sdkRefused("firstKey.readCreation", read.error);
		return { creation: read.creation, mail: made.mail, keys };
	};

	/** The first key after its mail: the mail's side, then the creation's key made, registered and possessed. */
	const firstKeyWith = async (
		front: BadFront,
		plain: { readonly token: string; readonly identifier: string; readonly code: string },
	): Promise<{ readonly credential: string } | Stopped> => {
		const side = await firstKeyMail(front, plain);
		if (stopped(side)) return side;
		return register(front, side.creation, side.keys);
	};

	return {
		start,
		signUp: signUpWith,
		approve,
		approveManagement,
		addKey,
		deleteKey,
		firstKeyStart,
		firstKeyMail,
		firstKey: firstKeyWith,
		register,
	};
}

export type LoginScreen = ReturnType<typeof loginScreen>;
