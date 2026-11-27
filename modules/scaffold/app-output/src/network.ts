/** The app's network declaration: each process's words as the packages' manifests state them, nothing derived. */

/** A word a package declares, and that package. */
export interface Word {
	readonly word: string;
	readonly from: string;
}

/** One process of the app: the script that starts it, the app's entries run as it, and its words. */
export interface Process {
	readonly name: string;
	readonly start: string;
	/** Scripts that assemble the same composition and never start it: they accept nothing. */
	readonly entries?: readonly string[];
	readonly words: readonly Word[];
}

/** The words each package given declares in `network`, in their order, each package's in its own. */
export const wordsOf = (
	packages: readonly {
		readonly name: string;
		readonly manifest: Readonly<Record<string, unknown>>;
	}[],
): Word[] =>
	packages.flatMap((p) =>
		[p.manifest.network ?? []].flat().map((word) => ({ word: String(word), from: p.name })),
	);

export const networkJson = (processes: readonly Process[]) =>
	`${JSON.stringify({ processes }, null, "\t")}\n`;
