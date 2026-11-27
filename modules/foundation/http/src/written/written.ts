/** A JSON answer as a server writes it: its text, or the paths of the nulls inside it (never their values). */
export type WrittenJson =
	| { readonly text: string | undefined }
	| { readonly nulls: readonly string[] };

/**
 * The paths of the nulls inside a value read back from JSON, at any depth: an object's member or an
 * array's element, in the order written. Walked by a stack of its own, not by recursion, so an answer
 * nested however deep JSON reads it is walked whole.
 */
function nullsIn(value: unknown): string[] {
	const found: string[] = [];
	// The value itself has no path (a top-level null is not inside it); a member named "" has one.
	const left: [unknown, string | undefined][] = [[value, undefined]];
	for (let next = left.pop(); next; next = left.pop()) {
		const [at, path] = next;
		if (at === null) {
			if (path !== undefined) found.push(path);
		} else if (Array.isArray(at)) {
			for (let i = at.length - 1; i >= 0; i--) left.push([at[i], `${path ?? ""}[${i}]`]);
		} else if (typeof at === "object") {
			const members = Object.entries(at);
			for (let i = members.length - 1; i >= 0; i--) {
				const [key, member] = members[i] as [string, unknown];
				left.push([member, path === undefined ? key : `${path}.${key}`]);
			}
		}
	}
	return found;
}

/**
 * A JSON answer's value as a server writes it (OpenID Connect Core §13.3: the provider writes no
 * member as null; one it has no value for is left out): the text, or the paths of the nulls inside it.
 * It reads back what JSON wrote, so NaN, Infinity, undefined in a list and a toJSON giving null are
 * nulls, each toJSON called once. A top-level null holds none inside it, and a value JSON writes as
 * nothing has no text: both are left as written. A value JSON cannot write (a cycle, a BigInt, a toJSON
 * that throws) throws as JSON throws; what a server answers then is its own.
 */
export function writtenJson(json: unknown): WrittenJson {
	const text: string | undefined = JSON.stringify(json);
	if (text === undefined) return { text };
	const nulls = nullsIn(JSON.parse(text));
	return nulls.length > 0 ? { nulls } : { text };
}
