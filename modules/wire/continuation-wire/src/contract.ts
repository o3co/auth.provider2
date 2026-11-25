import { z } from "zod";

/**
 * A statement's continuation (§C.2, §C.6, V24): what the screen's E_sig sends after a statement,
 * stage by stage. The words and the bytes are this wire's own; the statement itself, its purposes
 * and HPKE's suite and info are sdk-core-wire's.
 */

const stages = Object.freeze(["register", "delete", "rename", "sign-up"] as const);
export type ContinuationStageName = (typeof stages)[number];
const sealedStages = Object.freeze(["delete", "rename"] as const);
export type SealedStageName = (typeof sealedStages)[number];

/** A value's canonical text: keys sorted, no space, undefined members left out. This wire's rule for its bytes. */
function textOf(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(textOf).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${textOf(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** Base64url in its one spelling: a length bytes give, the last character carrying no bit past them. */
const oneSpelling = (text: string) => {
	const rest = text.length % 4;
	const last = alphabet.indexOf(text.charAt(text.length - 1));
	return rest !== 1 && last % (rest === 2 ? 16 : rest === 3 ? 4 : 1) === 0;
};
const utf8Length = (text: string) => {
	let bytes = 0;
	for (const char of text) {
		const point = char.codePointAt(0) ?? 0;
		bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
	}
	return bytes;
};

/** A continuation body's credential id: base64url in one spelling, 1364 characters at most (1023 bytes). */
const credentialId = z
	.string()
	.regex(/^[A-Za-z0-9_-]{1,1364}$/)
	.refine(oneSpelling);
/** A key's label: 1 to 64 code points, no control, format, surrogate or line separator. */
const label = z.string().regex(/^[^\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,64}$/u);
const bodies = Object.freeze({
	delete: z.object({ credential_id: credentialId }).strict(),
	rename: z.object({ credential_id: credentialId, label }).strict(),
	/** F1's continuation of an authorization's T (§3.13): no field; the Core makes the subject and its name. */
	"sign-up": z.object({}).strict(),
});
type BodyStage = keyof typeof bodies;
const isBodyStage = (stage: string): stage is BodyStage => Object.hasOwn(bodies, stage);

const plainBytes = 2048;
const sealedPlain = (stage: SealedStageName) =>
	z.object({ body: bodies[stage], sig: z.string().regex(/^[A-Za-z0-9_-]{85}[AQgw]$/) }).strict();

/**
 * The continuation's words: its stages, what E_sig signs for one (`of`) and how (`signature`), the
 * stages' bodies and what a body's hash covers (`bodyText`; a register's covers the response's text
 * as received), and the sealed stages' additional data and plaintext.
 */
export const continuations = Object.freeze({
	stages,
	sealed: sealedStages,
	aad: (stage: SealedStageName, statementHash: string, seq: number) =>
		textOf({ purpose: `continuation/${stage}`, h: statementHash, seq }),
	plainBytes,
	/** `{ body, sig }`'s canonical text padded with spaces to `plainBytes`; none for no shape or too long. */
	plainOf: (stage: SealedStageName, body: unknown, sig: string): string | undefined => {
		const read = sealedPlain(stage).safeParse({ body, sig });
		if (!read.success) return undefined;
		const text = textOf(read.data);
		const size = utf8Length(text);
		return size > plainBytes ? undefined : `${text}${" ".repeat(plainBytes - size)}`;
	},
	/** An opened text: `plainBytes` long, canonical then spaces alone, of its stage's shape; none otherwise. */
	readPlain: (
		stage: SealedStageName,
		text: string,
	): { readonly body: unknown; readonly sig: string } | undefined => {
		if (utf8Length(text) !== plainBytes) return undefined;
		const trimmed = text.replace(/ +$/, "");
		let parsed: unknown;
		try {
			parsed = JSON.parse(trimmed);
		} catch {
			return undefined;
		}
		const read = sealedPlain(stage).safeParse(parsed);
		return read.success && textOf(read.data) === trimmed ? read.data : undefined;
	},
	of: (stage: ContinuationStageName, statementHash: string, seq: number, bodyHash: string) =>
		textOf({ h: statementHash, stage, seq, body: bodyHash }),
	signature: Object.freeze({
		alg: "ES256",
		form: "r||s",
		over: "UTF-8 of continuations.of",
	} as const),
	bodies,
	/** The text a body's hash covers: its canonical text, for a stage with a body of its shape; none otherwise. */
	bodyText: (stage: string, body: unknown): string | undefined => {
		if (!isBodyStage(stage)) return undefined;
		const read = bodies[stage].safeParse(body);
		return read.success ? textOf(read.data) : undefined;
	},
});
