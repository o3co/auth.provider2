import { createHash } from "node:crypto";
import type { ClientAssertion } from "@mod/client-assertion";
import type { Client } from "@mod/clients";
import { Unavailable } from "@mod/kernel";
import { canonicalText, type SigningKey, typs } from "@mod/sdk-core-wire";
import { z } from "zod";
import type {
	JarReservations,
	RequestSource,
	StartFields,
	StoredReservation,
} from "../contract.ts";

export const sha256 = (data: string) => createHash("sha256").update(data).digest("base64url");

/** A refusal of the request, as OAuth names it, with why. */
export interface Refusal {
	readonly error: string;
	readonly description: string;
}
const refused = (error: string, description: string): { readonly refused: Refusal } => ({
	refused: { error, description },
});

/** A login's JAR as its source gave it: its bytes, with what `jarVerified` answered of them. */
export type Jar = Verified & { readonly jar: string };

/** What a JAR is verified with: its signature's check, this issuer, its longest life and the clock. */
export interface JarVerifying {
	readonly assertion: Pick<ClientAssertion, "verifySignedBy">;
	readonly issuer: string;
	/** The longest a JAR may still live when it is taken, in seconds. */
	readonly maxLifetimeS: number;
	readonly now: () => number;
}

/** A JAR's bytes verified: its claims, `jti` and expiry (seconds), or why it is refused. */
export type VerifiedJar =
	| {
			readonly kind: "verified";
			readonly claims: Readonly<Record<string, unknown>>;
			readonly jti: string;
			readonly exp: number;
	  }
	| { readonly kind: "refused"; readonly reason: string };
/** `jarVerified`'s answer where the JAR is taken. */
export type Verified = Extract<VerifiedJar, { readonly kind: "verified" }>;

/** How far a request's nbf may lie in the past, and how long it may live from it, in seconds (FAPI 2.0 Message Signing §5.3.1). */
const nbfWindowS = 60 * 60;

/**
 * A JAR taken as its client's: signed by it with the JAR's `typ`, its `iss` and `client_id` the
 * client, its `aud` this issuer, with a `jti`, an `nbf` at most 60 minutes past and an `exp` not
 * past, at most its longest life away and at most 60 minutes from its `nbf`.
 */
export async function jarVerified(
	p: JarVerifying,
	client: Client,
	jar: string,
): Promise<VerifiedJar> {
	const refused = (reason: string) => ({ kind: "refused", reason }) as const;
	const signed = await p.assertion.verifySignedBy(client, jar, typs.jar);
	if (signed.kind === "refused") return refused(signed.reason);
	const { claims } = signed;
	const { jti, exp, nbf } = claims;
	if (claims.iss !== client.id || claims.client_id !== client.id)
		return refused("the request is not its client's");
	if (claims.aud !== p.issuer && !(Array.isArray(claims.aud) && claims.aud.includes(p.issuer)))
		return refused("the request is not for this issuer");
	if (typeof jti !== "string" || jti === "") return refused("the request names no jti");
	if (typeof exp !== "number") return refused("the request names no exp");
	// FAPI 2.0 Message Signing §5.3.1 items 3 and 4: nbf named, no more than 60 minutes past, and
	// the request living no more than 60 minutes from it. An nbf past the clock skew ahead is the
	// signature check's refusal.
	if (typeof nbf !== "number") return refused("the request names no nbf");
	if (nbf * 1000 < p.now() - nbfWindowS * 1000)
		return refused("the request's nbf is more than 60 minutes past");
	if (exp - nbf > nbfWindowS) return refused("the request lives more than 60 minutes from its nbf");
	// Taken only before its expiry: whoever keeps it past then holds it the clock skew longer.
	if (exp * 1000 <= p.now()) return refused("the request has expired");
	if (exp * 1000 - p.now() > p.maxLifetimeS * 1000)
		return refused("the request lives longer than is taken");
	return { kind: "verified", claims, jti, exp };
}

export interface JarParts extends JarVerifying {
	readonly sources: readonly RequestSource[];
}

/** The request's JAR, from the one source that answers, verified as the client's. */
export async function jarOf(
	p: JarParts,
	fields: StartFields,
	client: Client,
): Promise<{ readonly jar: Jar } | { readonly refused: Refusal }> {
	const answers = (await Promise.all(p.sources.map((s) => s.jarOf(fields, client)))).filter(
		(a) => a !== undefined,
	);
	const [answer, ...more] = answers;
	if (!answer || more.length > 0)
		return refused("invalid_request", "the request is sent by exactly one of its ways");
	if ("refused" in answer) return { refused: answer.refused };
	const verified = await jarVerified(p, client, answer.jar);
	if (verified.kind === "refused") return refused("invalid_request_object", verified.reason);
	return { jar: { ...verified, jar: answer.jar } };
}

/** A start's answer, kept on its JAR's reservation and given again to the same request alone. */
const answerShape = z
	.object({ statement: z.string(), challenge: z.string(), create: z.boolean() })
	.strict();
export type StartAnswer = z.output<typeof answerShape>;

/**
 * A JAR's reservation: the digest of the start that used it, the call making its answer and until when
 * (kernel clock, ms), and that answer once made.
 */
const reservationShape = z
	.object({
		digest: z.string(),
		making: z.object({ by: z.string(), until: z.number() }).strict().optional(),
		answer: answerShape.optional(),
	})
	.strict();
type Reservation = z.output<typeof reservationShape>;
const reservationOf = (kept: StoredReservation | undefined): Reservation | undefined => {
	if (kept === undefined) return undefined;
	const read = reservationShape.safeParse(kept);
	if (!read.success) throw new Unavailable("authorize");
	return read.data;
};
const stored = (r: Reservation) => r as unknown as StoredReservation;

/** The digest a start is reserved by: the JAR's bytes and the screen's two keys (A20). */
export const startDigest = (jar: string, eEnc: string, eSig: SigningKey) =>
	sha256(canonicalText({ jar: sha256(jar), e_enc: eEnc, e_sig: eSig }));

/** How long a call making a start's answer holds it, in ms: past it, the same start makes it again. */
const makingMs = 30_000;

/**
 * A20: the JAR's one start. The first start for (client, `jti`) reserves it; one call at a time makes
 * its answer, holding it, and keeps it; the same start again (the same JAR and screen keys) is given
 * that answer, or told to ask again while a call makes it; any other is refused. A second statement is
 * made only where the call holding it fell before keeping its own, which never left the Core. The
 * reservation lives until the JAR's expiry and the clock skew past it.
 */
export function reserving(p: {
	readonly reservations: JarReservations;
	readonly skewS: number;
	readonly now: () => number;
	readonly token: () => string;
}) {
	/** Takes the making of the answer for this call, where none is kept and no live call holds it. */
	const claim = async (key: string, digest: string, by: string) => {
		const now = p.now();
		const changed = await p.reservations.change(key, (current) => {
			const r = reservationOf(current);
			const free = r?.making === undefined || r.making.until < now;
			return r?.digest === digest && r.answer === undefined && free
				? { value: stored({ ...r, making: { by, until: now + makingMs } }) }
				: undefined;
		});
		return reservationOf(changed?.after);
	};
	const keep = async (key: string, by: string, answer: StartAnswer) => {
		const changed = await p.reservations.change(key, (current) => {
			const r = reservationOf(current);
			if (r?.making?.by !== by || r.answer !== undefined) return undefined;
			const { making: _done, ...rest } = r;
			return { value: stored({ ...rest, answer }) };
		});
		return reservationOf(changed?.after);
	};
	/** Lets go of a making that made no answer, so the same start may try again at once. */
	const release = (key: string, by: string) =>
		p.reservations.change(key, (current) => {
			const r = reservationOf(current);
			if (r?.making?.by !== by) return undefined;
			const { making: _done, ...rest } = r;
			return { value: stored(rest) };
		});
	const busy = refused("temporarily_unavailable", "the request's start is being made; ask again");

	return async (
		client: string,
		jar: Jar,
		digest: string,
		make: () => Promise<StartAnswer | { readonly refused: Refusal }>,
	): Promise<StartAnswer | { readonly refused: Refusal }> => {
		const key = sha256(canonicalText({ client, jti: jar.jti }));
		const lifetimeMs = (jar.exp + p.skewS) * 1000 - p.now();
		await p.reservations.create(key, stored({ digest }), lifetimeMs);
		const r = reservationOf(await p.reservations.read(key));
		if (r?.digest !== digest) return refused("invalid_request", "the request was used already");
		if (r.answer) return r.answer;
		const by = p.token();
		const held = await claim(key, digest, by);
		if (held?.answer) return held.answer;
		if (held?.making?.by !== by) return busy;
		// A making that throws lets go too, so the same start may try again at once.
		const made = await make().catch(async (error: unknown) => {
			await release(key, by);
			throw error;
		});
		if ("refused" in made) {
			await release(key, by);
			return made;
		}
		const kept = await keep(key, by, made);
		return kept?.answer ?? busy;
	};
}
