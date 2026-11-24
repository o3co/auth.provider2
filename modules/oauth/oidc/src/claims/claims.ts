import {
	type Constraint,
	type Named,
	type Scalar,
	type Selection,
	selectionLimits,
	type Target,
	withinLimits,
} from "@mod/claims-selection";
import { type UserAttributes, userAttribute } from "@mod/users";

/** A released claim's value: a string, a boolean, or a list of strings. */
export type Claim = string | boolean | readonly string[];

/** One claim: users' attribute it is read from, and the value it takes from it (undefined: left out). */
interface Row {
	readonly claim: string;
	readonly attribute: keyof UserAttributes;
	readonly read: (value: unknown) => Claim | undefined;
}

const text = (value: unknown) => (typeof value === "string" ? value : undefined);
const flag = (value: unknown) => (typeof value === "boolean" ? value : undefined);
const texts = (value: unknown) =>
	Array.isArray(value)
		? Object.freeze(value.filter((item): item is string => typeof item === "string"))
		: undefined;

const table = new Map<string, readonly Row[]>([
	[
		"profile",
		[
			{ claim: "name", attribute: userAttribute.name, read: text },
			{ claim: "picture", attribute: userAttribute.picture, read: text },
		],
	],
	[
		"email",
		[
			{ claim: "email", attribute: userAttribute.email, read: text },
			{ claim: "email_verified", attribute: userAttribute.emailVerified, read: flag },
		],
	],
	["groups", [{ claim: "groups", attribute: userAttribute.groups, read: texts }]],
]);

/** The scopes the table releases claims for, in the table's order. */
export const tableScopes: readonly string[] = Object.freeze([...table.keys()]);

/** The claims the table can release, in the table's order. */
export const tableClaims: readonly string[] = Object.freeze(
	[...table.values()].flatMap((rows) => rows.map((row) => row.claim)),
);

const scopeByClaim = new Map(
	[...table].flatMap(([scope, rows]) => rows.map((row) => [row.claim, scope] as const)),
);

/** The scope a table claim belongs to; none for a claim outside the table. */
export const scopeOfClaim = (claim: string): string | undefined => scopeByClaim.get(claim);

/** Whether a released value holds its constraint: equal, type and all, to the value or one of the values; a list never does. */
const holds = (value: Claim, constraint: Constraint) =>
	!Array.isArray(value) &&
	(constraint.value !== undefined
		? value === constraint.value
		: (constraint.values ?? []).includes(value as string | boolean));

/**
 * The claims the table releases from `attributes` for the scope words that match a row exactly,
 * and for the table claims `asked` names; then, of all of them, those its constraints do not hold
 * back (OpenID Connect Core §5.5.1).
 */
export function claimsOf(
	attributes: Readonly<Record<string, unknown>>,
	scope: readonly string[],
	asked?: Target,
): Readonly<Record<string, Claim>> {
	const named = new Set((asked?.names ?? []).map(({ name }) => name));
	const rows = [
		...[...new Set(scope)].flatMap((word) => table.get(word) ?? []),
		...[...table.values()].flat().filter((row) => named.has(row.claim)),
	];
	const released: Record<string, Claim> = {};
	for (const row of rows) {
		const value = Object.hasOwn(attributes, row.attribute)
			? row.read(attributes[row.attribute])
			: undefined;
		if (value !== undefined) released[row.claim] = value;
	}
	for (const constraint of asked?.constraints ?? []) {
		const value = Object.hasOwn(released, constraint.name) ? released[constraint.name] : undefined;
		if (value !== undefined && !holds(value, constraint)) delete released[constraint.name];
	}
	return Object.freeze(released);
}

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** What a `claims` request parameter asks (OpenID Connect Core §5.5), as the Core acts on it. */
export interface ClaimsAsked {
	/** The `sub` values each member asks: the subject must be one of every list. */
	readonly subs: readonly (readonly string[])[];
	/** The `acr` each member asks (§5.5.1.1), kept apart: an essential one is met only by one of its values, any where it names none. */
	readonly acr: readonly { readonly essential: boolean; readonly values: readonly string[] }[];
	/** The table claims it names beyond the scope, and their constraints, by target. */
	readonly selection: Selection;
}

const malformed = "malformed";
/** An individual claim request (§5.5.1): `null`, or `essential` a boolean and `value` or a non-empty `values` (not both). */
function individual<T>(entry: unknown, fits: (v: unknown) => v is T, most: number) {
	if (entry === null) return {};
	if (!isObject(entry)) return malformed;
	const { essential, value, values } = entry;
	if (essential !== undefined && typeof essential !== "boolean") return malformed;
	if (value !== undefined && !fits(value)) return malformed;
	const listed = Array.isArray(values) && values.length > 0 && values.length <= most;
	if (values !== undefined && !(listed && (values as unknown[]).every(fits))) return malformed;
	// Both together leave which one is asked unclear.
	if (value !== undefined && values !== undefined) return malformed;
	return {
		...(value !== undefined ? { value: value as T } : {}),
		...(values !== undefined ? { values: values as T[] } : {}),
	};
}

const isText = (v: unknown): v is string => typeof v === "string";
const isScalar = (v: unknown): v is Scalar =>
	(typeof v === "string" && v.length <= selectionLimits.valueLength) ||
	typeof v === "boolean" ||
	(typeof v === "number" && Number.isFinite(v));

/** The `sub` values a member asks for: none where it names none, or names it with no value. */
function subOf(part: Record<string, unknown>) {
	if (!Object.hasOwn(part, "sub")) return undefined;
	const asked = individual(part.sub, isText, Number.POSITIVE_INFINITY);
	if (asked === malformed) return malformed;
	const values = [...(asked.value === undefined ? [] : [asked.value]), ...(asked.values ?? [])];
	return values.length > 0 ? values : undefined;
}

/** The `acr` a member asks for: none where it names none. */
function acrOf(part: Record<string, unknown>) {
	if (!Object.hasOwn(part, "acr")) return undefined;
	const asked = individual(part.acr, isText, Number.POSITIVE_INFINITY);
	if (asked === malformed) return malformed;
	const values = [...(asked.value === undefined ? [] : [asked.value]), ...(asked.values ?? [])];
	return { essential: isObject(part.acr) && part.acr.essential === true, values };
}

/** The table claims a member names, and their constraints; any other member is passed over. */
function targetOf(part: Record<string, unknown>): Target | typeof malformed {
	const names: Named[] = [];
	const constraints: Constraint[] = [];
	for (const [name, entry] of Object.entries(part)) {
		const scope = scopeOfClaim(name);
		if (scope === undefined) continue;
		const asked = individual(entry, isScalar, selectionLimits.values);
		if (asked === malformed) return malformed;
		names.push({ name, scope });
		if (asked.value !== undefined) constraints.push({ name, value: asked.value });
		if (asked.values !== undefined) constraints.push({ name, values: asked.values });
	}
	return { names, constraints };
}

/**
 * A `claims` parameter (OpenID Connect Core §5.5), as a JSON object, read once: the `sub` values each
 * member asks, and the table claims each names beyond the scope with their constraints. Malformed
 * where it is no object, a member it reads is of no shape §5.5.1 gives, or what it names is past
 * the bounds a selection keeps; a member or claim it does not read is passed over.
 */
export function claimsAsked(value: unknown): ClaimsAsked | typeof malformed {
	if (!isObject(value)) return malformed;
	const members = [value.id_token, value.userinfo];
	// A member is an object where it is given at all.
	if (members.some((part) => part !== undefined && !isObject(part))) return malformed;
	const parts = members.map((part) => (isObject(part) ? part : {}));
	const subs = parts.map(subOf);
	const acr = parts.map(acrOf);
	if (acr.includes(malformed)) return malformed;
	const [idToken, userinfo] = parts.map(targetOf);
	if (subs.includes(malformed) || idToken === malformed || userinfo === malformed) return malformed;
	if (idToken === undefined || userinfo === undefined) return malformed;
	const selection = { idToken, userinfo };
	if (!withinLimits(selection)) return malformed;
	return {
		subs: subs.filter((part): part is string[] => part !== undefined && part !== malformed),
		acr: acr.filter((part) => part !== undefined && part !== malformed),
		selection,
	};
}
