/** A parse issue as zod gives it: a union's carries each branch's issues. */
export interface Issue {
	readonly path: readonly PropertyKey[];
	readonly code?: string;
	readonly errors?: readonly (readonly Issue[])[];
}

/** How many of a branch's own keys it is off at, however many issues each holds. */
const spread = (issues: readonly Issue[]) =>
	new Set(issues.map((i) => String(i.path[0] ?? ""))).size;

/**
 * Where an answer is off a form, by the form's own keys and indexes, each once: a union's by its
 * nearest branch, the one off at the fewest of its own keys. Never an issue's message or keys,
 * which carry the answer's own content.
 */
export const issuePaths = (issues: readonly Issue[], at: readonly PropertyKey[] = []): string[] => [
	...new Set(
		issues.flatMap((issue) => {
			const path = [...at, ...issue.path];
			// A discriminated union's unknown discriminator has no branch: told at its own path.
			const nearest = issue.errors?.length
				? issue.errors.reduce((a, b) => (spread(b) < spread(a) ? b : a))
				: undefined;
			return issue.code === "invalid_union" && nearest
				? issuePaths(nearest, path)
				: [path.map(String).join(".") || "(top)"];
		}),
	),
];
