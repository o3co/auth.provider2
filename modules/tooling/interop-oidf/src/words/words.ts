/** Who answers a refusal a run sees: the Front (the wire's form), the Core, or a role of the harness. */
export const refusers = ["front", "core", "harness"] as const;
export type Refuser = (typeof refusers)[number];

/** Where a refusal is answered. */
export const places = ["par", "start", "finish", "token", "resource"] as const;
export type Place = (typeof places)[number];

/** A refusal the provider answers for one of the ledger's rows, as it is written on the wire. */
export interface Word {
	/** The ledger row it answers for. */
	readonly key: string;
	readonly refuser: Refuser;
	readonly place: Place;
	/** The OAuth `error`. */
	readonly error: string;
	/** The `error_description`, exactly. */
	readonly description: string;
	/** Where the same words answer two rows, whether the request carried a DPoP header tells them apart. */
	readonly dpopHeader?: boolean;
	/** Where the same words answer another cause, whether this start's `request_uri` was started before tells them apart. */
	readonly startedBefore?: boolean;
	/** The same words answer other causes too: a refusal in them is never the row's alone. */
	readonly shared?: true;
}

/** A refusal a run saw, as the front or a role recorded it. */
export interface Seen {
	readonly refuser: Refuser;
	readonly place: Place;
	readonly error: string;
	readonly description: string;
	readonly dpopHeader: boolean;
	/**
	 * A start whose `request_uri` an earlier start of the run named and was not refused: then the
	 * reservation holds this JAR, and a refusal is of the screen's keys alone.
	 */
	readonly startedBefore: boolean;
}

/** What a refusal seen says of the ledger: one row, rows it cannot tell apart, or none. */
export type Reading =
	| { readonly kind: "observed"; readonly key: string }
	| { readonly kind: "unconfirmed"; readonly keys: readonly string[] }
	| { readonly kind: "none" };

/** A word answered alike at PAR and at the start: `authorize`'s request check, which both call. */
const atBoth = (word: Omit<Word, "place">): readonly Word[] =>
	(["par", "start"] as const).map((place) => ({ ...word, place }));

/**
 * The provider's words for the ledger's rows, as its modules answer them today: a way a row shows with
 * no refusal (`form-post-required` as the suite reads a callback's query) has none.
 */
export const words: readonly Word[] = [
	{
		key: "jar-typ-required",
		refuser: "core",
		place: "par",
		error: "invalid_request_object",
		description: "not of the typ asked",
	},
	{
		key: "jar-jti-required",
		refuser: "core",
		place: "par",
		error: "invalid_request_object",
		description: "the request names no jti",
	},
	{
		key: "par-jar-lifetime",
		refuser: "core",
		place: "par",
		error: "invalid_request_object",
		description: "the request lives longer than is taken",
	},
	// The request check's word for a JAR naming no dpop_jkt, before any proof is read.
	{
		key: "jar-dpop-jkt-required",
		refuser: "core",
		place: "par",
		error: "invalid_request",
		description: "missing_item:dpop_jkt",
		dpopHeader: false,
	},
	{
		key: "par-dpop-header-only",
		refuser: "core",
		place: "par",
		error: "invalid_request",
		description: "missing_item:dpop_jkt",
		dpopHeader: true,
	},
	{
		key: "jar-dpop-jkt-required",
		refuser: "core",
		place: "start",
		error: "invalid_request",
		description: "missing_item:dpop_jkt",
	},
	{
		key: "rar-refused",
		refuser: "core",
		place: "par",
		error: "invalid_request",
		description: "authorization_details are not taken",
	},
	{
		key: "rar-refused",
		refuser: "core",
		place: "token",
		error: "invalid_request",
		description: "authorization_details are not taken",
	},
	// The same item as a JAR's claim: the request object's, by its spelling.
	...atBoth({
		key: "rar-refused",
		refuser: "core",
		error: "invalid_request_object",
		description: "refused_item:authorization_details",
	}),
	...atBoth({
		key: "form-post-required",
		refuser: "core",
		error: "invalid_request",
		description: "missing_item:response_mode",
	}),
	...atBoth({
		key: "state-required",
		refuser: "core",
		error: "invalid_request",
		description: "missing_item:state",
	}),
	...atBoth({
		key: "nonce-required",
		refuser: "core",
		error: "invalid_request",
		description: "missing_item:nonce",
	}),
	...atBoth({
		key: "state-nonce-bound",
		refuser: "core",
		error: "invalid_request",
		description: "state is longer than 512 bytes",
	}),
	...atBoth({
		key: "state-nonce-bound",
		refuser: "core",
		error: "invalid_request",
		description: "nonce is longer than 512 bytes",
	}),
	...atBoth({
		key: "prompt-none-at-par",
		refuser: "core",
		error: "login_required",
		description: "every login asks the person's passkey",
	}),
	...atBoth({
		key: "claims-null-nested",
		refuser: "core",
		error: "invalid_request_object",
		description: "item:claims",
		// Also a `claims` that is no JSON object, the standard's own refusal.
		shared: true,
	}),
	{
		key: "request-uri-once",
		refuser: "core",
		place: "start",
		error: "invalid_request",
		description: "the request was used already",
		// Also another JAR under the same `jti`: only a start of a `request_uri` started before is this row's.
		startedBefore: true,
	},
	// No source answered the start: one carrying neither `request` nor `request_uri`, or a `request_uri`
	// where no `par` is composed.
	{
		key: "jar-required",
		refuser: "core",
		place: "start",
		error: "invalid_request",
		description: "the request is sent by exactly one of its ways",
		shared: true,
	},
	// A JAR by value where only pushed ones are taken (par's pushed-only, F4).
	{
		key: "jar-required",
		refuser: "core",
		place: "start",
		error: "invalid_request",
		description: "a request by value is not taken",
	},
	// The refresh grant answers every refused token alike, so it tells nothing about why.
	{
		key: "refresh-dpop-bound",
		refuser: "core",
		place: "token",
		error: "invalid_grant",
		description: "invalid refresh token",
		shared: true,
	},
];

const matches = (word: Word, seen: Seen) =>
	word.refuser === seen.refuser &&
	word.place === seen.place &&
	word.error === seen.error &&
	word.description === seen.description &&
	(word.dpopHeader === undefined || word.dpopHeader === seen.dpopHeader) &&
	(word.startedBefore === undefined || word.startedBefore === seen.startedBefore);

/** Words the provider answers for many causes, none a ledger row: a refusal in them is unconfirmed, of no row. */
export type ManyCauses = Pick<Word, "refuser" | "place" | "error" | "description">;

const frontShape = /^[a-z][A-Za-z]*: [a-z][A-Za-z]*$/;

/** Who refused, by the words alone (one origin): the Front's are front-relay's `<field>: <code>`, a shape no Core word has. */
export const refuserOf = (description: string): "front" | "core" =>
	frontShape.test(description) ? "front" : "core";

/** Words answering many causes no row names: the client's authentication, one for every fault of an assertion. */
export const manyCauses: readonly ManyCauses[] = (["par", "token"] as const).map((place) => ({
	refuser: "core",
	place,
	error: "invalid_client",
	description: "the client is not authenticated",
}));

/**
 * What a refusal seen says: the one row whose words it is where only that row's words fit and they are
 * no other cause's; unconfirmed where they are shared or more than one row's, or words of many causes no
 * row names (no rows); none where no words fit.
 */
export function readingOf(
	seen: Seen,
	table: readonly Word[] = words,
	apart: readonly ManyCauses[] = manyCauses,
): Reading {
	const fit = table.filter((word) => matches(word, seen));
	const keys = [...new Set(fit.map((word) => word.key))];
	const [only] = keys;
	if (only === undefined) {
		const many = apart.some(
			(w) =>
				w.refuser === seen.refuser &&
				w.place === seen.place &&
				w.error === seen.error &&
				w.description === seen.description,
		);
		return many ? { kind: "unconfirmed", keys: [] } : { kind: "none" };
	}
	if (keys.length > 1 || fit.some((word) => word.shared)) return { kind: "unconfirmed", keys };
	return { kind: "observed", key: only };
}

/**
 * Why a table may not be taken, if anything: a word for no row of the ledger, a description left
 * empty, or two rows' words that a request cannot tell apart unless both say they are shared.
 */
export function wordsProblems(table: readonly Word[], keys: readonly string[]): string[] {
	const problems: string[] = [];
	for (const word of table) {
		if (!keys.includes(word.key)) problems.push(`${word.key}: no row of the ledger`);
		if (word.description === "" || word.error === "")
			problems.push(`${word.key}: its words are empty`);
	}
	for (const [i, one] of table.entries()) {
		for (const other of table.slice(i + 1)) {
			const overlap =
				one.key !== other.key &&
				one.refuser === other.refuser &&
				one.place === other.place &&
				one.error === other.error &&
				one.description === other.description &&
				(one.dpopHeader === undefined ||
					other.dpopHeader === undefined ||
					one.dpopHeader === other.dpopHeader) &&
				(one.startedBefore === undefined ||
					other.startedBefore === undefined ||
					one.startedBefore === other.startedBefore);
			if (overlap && !(one.shared && other.shared))
				problems.push(
					`${one.key} and ${other.key}: the same words, and not both say they are shared`,
				);
		}
	}
	return problems;
}
