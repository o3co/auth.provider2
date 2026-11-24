import { deepFreeze, isUnavailable, type Log, Unavailable } from "@mod/kernel";
import {
	type Created,
	isAttributeValue,
	isWellFormedSubject,
	type Ledger,
	userAttribute,
	type Verified,
} from "../contract.ts";
import { none, type UserSource, unanswerable } from "../registered.ts";

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

function copyOf(given: unknown): unknown {
	try {
		return structuredClone(given);
	} catch {
		throw new Unavailable("users");
	}
}

/** A name the ledger wrote, safe for one log field. */
const loggable = (name: string) => [...name.replace(/[\p{Cc}\p{Cf}]/gu, "")].slice(0, 200).join("");

/**
 * The attributes whose values users accepts; each other is left out, logged by name and never by
 * value. An email's verification goes with the email, so it is left out with one left out.
 */
function acceptedOf(attributes: Record<string, unknown>, log: Log): Record<string, unknown> {
	const dropped = (name: string) => {
		log.warn("users.attribute_dropped", { attribute: loggable(name) });
		return false;
	};
	const emailKept = isAttributeValue(userAttribute.email, attributes[userAttribute.email]);
	const accepted = (name: string, value: unknown) => {
		if (name === userAttribute.emailVerified && !emailKept) return dropped(name);
		return isAttributeValue(name, value) || dropped(name);
	};
	return Object.fromEntries(
		Object.entries(attributes).filter(([name, value]) => accepted(name, value)),
	);
}

/** Reads a ledger's copied answer into a frozen user of its declared fields; a malformed answer, an ill-formed subject or another subject's user is unavailable. */
function readAnswer(answer: unknown, log: Log, askedSubject?: string): Verified {
	if (isObject(answer) && answer.kind === "none") return none;
	const user = isObject(answer) && answer.kind === "user" ? answer.user : undefined;
	if (!isObject(user) || !isObject(user.attributes) || typeof user.subject !== "string") {
		throw new Unavailable("users");
	}
	const { subject, attributes } = user;
	if (!isWellFormedSubject(subject) || (askedSubject !== undefined && subject !== askedSubject)) {
		throw new Unavailable("users");
	}
	return deepFreeze({ kind: "user", user: { subject, attributes: acceptedOf(attributes, log) } });
}

/** Any failure of the ledger is unavailable, never passed on as it came. */
async function fromLedger(call: () => Promise<unknown>): Promise<unknown> {
	try {
		return await call();
	} catch (error) {
		throw isUnavailable(error) ? error : new Unavailable("users");
	}
}

/** A create's copied answer: `exists`, or the user made, read as any answer is; anything else is unavailable. */
function readCreated(answer: unknown, log: Log): Created {
	if (isObject(answer) && answer.kind === "exists") return deepFreeze({ kind: "exists" });
	if (!isObject(answer) || answer.kind !== "created") throw new Unavailable("users");
	const read = readAnswer({ kind: "user", user: answer.user }, log);
	if (read.kind !== "user") throw new Unavailable("users");
	return deepFreeze({ kind: "created", user: read.user });
}

export function contributedSource(ledger: Ledger, log: Log): UserSource {
	const { byIdentifier, create, keep } = ledger;
	const lookingUp = byIdentifier
		? {
				byIdentifier: async (identifier: string) =>
					identifier === ""
						? none
						: readAnswer(
								copyOf(await fromLedger(() => byIdentifier.call(ledger, identifier))),
								log,
							),
			}
		: {};
	const keeping = keep
		? {
				keep: async (subject: string, identifier: string) => {
					const answer = await fromLedger(() => keep.call(ledger, subject, identifier));
					if (answer === "kept" || answer === "conflict") return answer;
					throw new Unavailable("users");
				},
			}
		: {};
	const creating = create
		? {
				create: async (identifier: string) => {
					if (identifier === "") throw new TypeError("users: an empty identifier names no one");
					return readCreated(copyOf(await fromLedger(() => create.call(ledger, identifier))), log);
				},
			}
		: {};
	return {
		verify: async (identifier, password) =>
			identifier === ""
				? none
				: readAnswer(copyOf(await fromLedger(() => ledger.verify(identifier, password))), log),

		bySubject: async (subject) => {
			if (!isWellFormedSubject(subject)) return none;
			const answer = copyOf(await fromLedger(() => ledger.bySubject(subject)));
			return isObject(answer) && answer.kind === "unanswerable"
				? unanswerable
				: readAnswer(answer, log, subject);
		},
		...lookingUp,
		...creating,
		...keeping,
	};
}
