import { contract, extensionPoint } from "@mod/kernel";

/** The amr a way of logging in can prove, under its name; the names are its own words, never read here. */
export interface AmrSource {
	readonly name: string;
	readonly amr: readonly string[];
}

/** The ways of logging in a composition declares, each by the amr it can prove: what the table is checked against. */
export const amrSources = extensionPoint<AmrSource>("acr.amr-sources", {
	multiplicity: "keyed",
	keyOf: (source) => source.name,
});

/** Decisions on the acr a request asks for; the table stays here. */
export interface Acr {
	/** The acr the table knows among `asked`, the request's space-separated acr_values, in the order asked. */
	known(asked: string): readonly string[];
	/** The first of these acr the amr meet, if any. */
	met(known: readonly string[], amr: readonly string[]): string | undefined;
	/** The session's current acr: the first in the table's order the amr meet, if any. */
	current(amr: readonly string[]): string | undefined;
}

export const acr = contract<Acr>("acr");
