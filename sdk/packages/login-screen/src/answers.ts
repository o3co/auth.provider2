import { payloads } from "@mod/sdk-core-wire";
import { deepFreeze, fromBase64url } from "./bytes.ts";
import type { Sealed } from "./hpke.ts";

/** The forms a success's body may be of: sdk-core-wire's `payloads.answers`, by the names front-core-wire's `overHttp` gives. */
export type AnswerForm = keyof typeof payloads.answers;

/** What each form reads to: the values the SDK's steps take. */
export interface Answers {
	/** ②'s answer: T and whether a passkey may be made first. Its challenge is not given: the screen computes it from T. */
	readonly authorization: { readonly statement: string; readonly create: boolean };
	/** A statement's compact JWS, which its step's reader verifies. */
	readonly statement: string;
	/** A sealed answer's encapsulated key and ciphertext, as bytes; whether `enc` is a point of the curve is for the opening. */
	readonly sealed: Sealed;
	/** A nonce, base64url, as `firstKey.start` and `mail` take it. */
	readonly nonce: string;
}

const readers: { readonly [F in AnswerForm]: (json: unknown) => Answers[F] | undefined } = {
	authorization: (json) => {
		const read = payloads.answers.authorization.safeParse(json);
		return read.success
			? deepFreeze({ statement: read.data.statement, create: read.data.create })
			: undefined;
	},
	statement: (json) => {
		const read = payloads.answers.statement.safeParse(json);
		return read.success ? read.data.statement : undefined;
	},
	sealed: (json) => {
		const read = payloads.answers.sealed.safeParse(json);
		if (!read.success) return undefined;
		const enc = fromBase64url(read.data.sealed.enc);
		const ct = fromBase64url(read.data.sealed.ct);
		return enc && ct ? Object.freeze({ enc, ct }) : undefined;
	},
	nonce: (json) => {
		const read = payloads.answers.nonce.safeParse(json);
		return read.success ? read.data.nonce : undefined;
	},
};

/**
 * A success's body, as the page parsed it (`response.json()`), read by its form: by sdk-core-wire's
 * schema (an extra field, a missing one or another form's is none), to the value the SDK's steps
 * take; none otherwise, and for a form it does not know. A form given as a literal reads to that
 * form's value; one given as text (`overHttp`'s `answer`) to any form's. Nothing is fetched, and a
 * refusal's body is the page's to read.
 */
function read<F extends AnswerForm>(form: F, json: unknown): Answers[F] | undefined;
function read(form: string, json: unknown): Answers[AnswerForm] | undefined;
function read(form: string, json: unknown): Answers[AnswerForm] | undefined {
	return Object.hasOwn(readers, form) ? readers[form as AnswerForm](json) : undefined;
}

/** A success's body read to the SDK's values. */
export const answers = Object.freeze({ read });
