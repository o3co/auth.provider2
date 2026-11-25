import { deepFreeze, type Log, Unavailable } from "@mod/kernel";
import { usersWire } from "@mod/ledger-wire";
import {
	jsonObjectOf,
	type Narrower,
	type Outbound,
	type OutboundResponse,
	postJson,
} from "@mod/outbound";
import type { ConfiguredUrl } from "@mod/url-setting";
import {
	type Created,
	isWellFormedSubject,
	type User,
	userAttribute,
	type Verified,
} from "@mod/users";

/** What the calls are made with: outbound, the credential if any, the narrower of each URL, and the log. */
export interface CallParts {
	readonly out: Outbound;
	readonly credential: string | undefined;
	readonly narrowerOf: (url: ConfiguredUrl) => Narrower;
	readonly warn: Log["warn"];
}

/** The ledger's calls: the password call, a lookup that posts what it looks up, a create and an identifierless create. */
export interface Calls {
	verify(url: ConfiguredUrl, identifier: string, password: string): Promise<Verified>;
	lookup(url: ConfiguredUrl, asked: Readonly<Record<string, string>>): Promise<Verified>;
	create(url: ConfiguredUrl, identifier: string): Promise<Created>;
	createIdentifierless(url: ConfiguredUrl, key: string): Promise<User>;
}

const none: Verified = deepFreeze({ kind: "none" });
const exists: Created = deepFreeze({ kind: "exists" });
/** The ledger's fields kept as given, each with users' name for it. */
const keptFields = [
	["email", userAttribute.email],
	["name", userAttribute.name],
	["picture", userAttribute.picture],
	["groups", userAttribute.groups],
] as const;
const isName = (value: unknown): value is string => typeof value === "string" && value !== "";

/** The ledger's user `{id, ...}` as a new frozen user, or undefined when it is not one. */
function userOf(answer: Readonly<Record<string, unknown>>) {
	const { id, emailVerified } = answer;
	if (!isWellFormedSubject(id)) return undefined;
	const attributes = Object.fromEntries([
		...keptFields.filter(([field]) => Object.hasOwn(answer, field)).map(([f, a]) => [a, answer[f]]),
		// Only a boolean says whether the email is verified, and only beside the email it is about.
		...(typeof emailVerified === "boolean" && Object.hasOwn(answer, "email")
			? [[userAttribute.emailVerified, emailVerified]]
			: []),
	]);
	return deepFreeze({ kind: "user", user: { subject: id, attributes } } as const);
}

export function calls(parts: CallParts): Calls {
	const { out, credential, narrowerOf, warn } = parts;
	/** Logs why the ledger failed, by its kind or status alone, and answers unavailable. */
	const failed = (why: { reason: string } | { status: number; reason?: string }) => {
		warn("users-http.ledger_failed", why);
		return new Unavailable("users-http");
	};
	const post = (url: ConfiguredUrl, body: unknown) =>
		postJson(out, { url, body, credential, narrower: narrowerOf(url) }, (reason) =>
			failed({ reason }),
		);
	/** An answer of `status` read once into a user, or unavailable. */
	const userIn = (answer: OutboundResponse, wanted: (user: object) => boolean, status = 200) => {
		if (answer.status !== status) throw failed({ status: answer.status });
		const read = jsonObjectOf(answer, status);
		const user = read.kind === "object" && wanted(read.value) ? userOf(read.value) : undefined;
		if (!user) throw failed({ reason: "malformed" });
		return user;
	};
	/**
	 * None where the ledger says it knows no such user, unavailable where a 404 or 410 does not say
	 * so (a bare 404 may be a wrong path, a gateway or a ledger hiding itself), undefined otherwise.
	 */
	const noUserIn = (answer: OutboundResponse) => marked(answer, usersWire.noUser, none);
	/** `exists` where a create's 409 says the identifier is taken, unavailable where it does not, undefined otherwise. */
	const takenIn = (answer: OutboundResponse) => marked(answer, usersWire.taken, exists);
	/** `meaning` where the answer's status is one of `words` and its body says that word, unavailable where unsaid. */
	function marked<T>(
		answer: OutboundResponse,
		words: Readonly<Record<number, string>>,
		meaning: T,
	) {
		const said = words[answer.status];
		if (said === undefined) return undefined;
		const read = jsonObjectOf(answer, answer.status);
		if (read.kind === "object" && read.value.error === said) return meaning;
		throw failed({ status: answer.status, reason: "unmarked" });
	}
	return {
		async verify(url, identifier, password) {
			// The identifier under the name the ledger's password call reads.
			const answer = await post(url, usersWire.verify(identifier, password));
			// Only a 404 or 410 saying so refuses the user: a 401 or 403 may come from a proxy before the
			// ledger, or refuse the credential, and read as a wrong password it would hold logins back.
			return (
				noUserIn(answer) ??
				userIn(answer, (user) => isName((user as { username?: unknown }).username))
			);
		},
		async lookup(url, asked) {
			const answer = await post(url, asked);
			return noUserIn(answer) ?? userIn(answer, () => true);
		},
		async create(url, identifier) {
			const answer = await post(url, usersWire.create(identifier));
			const taken = takenIn(answer);
			if (taken) return taken;
			const { user } = userIn(answer, () => true, usersWire.created);
			return deepFreeze({ kind: "created", user });
		},
		// The same key is answered the same subject: asked again, the ledger makes no second one.
		async createIdentifierless(url, key) {
			const answer = await post(url, usersWire.createIdentifierless(key));
			return userIn(answer, () => true, usersWire.created).user;
		},
	};
}
