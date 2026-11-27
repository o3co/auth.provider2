/** What each reached package asks of the operator, as its manifest declares it, rendered for the guide. */

/** One line: shown always, or only where no adapter of its package is composed; a value the operator decides where `decides`. */
export type Ask =
	| string
	| { readonly line: string; readonly decides?: true; readonly unadapted?: true };

/** What a package declares for the guide: its lines, the owner it adapts, and the name it registers under its owner. */
export interface Asked {
	readonly name: string;
	readonly asks?: readonly Ask[] | undefined;
	readonly adapts?: string | undefined;
	readonly registersAs?: string | undefined;
}

/** The mark a line may hold: the composed adapters' names, else its own. */
const adaptersMark = "{adapters}";

/**
 * The guide's two lists, each line as `- …`, in the packages' order: what the composition asks
 * (`chosen`), and the values the operator decides (`decides`).
 */
export function askedOf(names: readonly string[], declared: readonly Asked[]) {
	const reached = declared.filter((d) => names.includes(d.name));
	const chosen: string[] = [];
	const decides: string[] = [];
	for (const name of names) {
		const own = reached.find((d) => d.name === name);
		const adapters = reached.filter((d) => d.adapts === name);
		const named = adapters.flatMap((a) => (a.registersAs ? [a.registersAs] : []));
		const filled = (named.length > 0 ? named : own?.registersAs ? [own.registersAs] : []).join(
			", ",
		);
		for (const ask of own?.asks ?? []) {
			const { line, decides: decided, unadapted } = typeof ask === "string" ? { line: ask } : ask;
			if (unadapted && adapters.length > 0) continue;
			(decided ? decides : chosen).push(`- ${line.replaceAll(adaptersMark, filled)}`);
		}
	}
	return { chosen, decides };
}
