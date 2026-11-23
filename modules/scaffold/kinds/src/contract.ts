/** The kinds a package's manifest names, each the one word the product and its checks read. */
export const kinds = {
	common: "common",
	/** The contract of a wire an outside system speaks with the provider; no workspace dependency, not product. */
	protocol: "protocol",
	foundation: "foundation",
	capability: "capability",
	feature: "feature",
	adapter: "adapter",
	assembly: "assembly",
	wiring: "wiring",
	verification: "verification",
	/** A program that runs outside the provider's process, in a trust domain of its own. */
	companion: "companion",
} as const;

export type Kind = (typeof kinds)[keyof typeof kinds];

/** Kinds from the bottom up: a kind may depend on its own level and those below. */
export const kindOrder: readonly (readonly Kind[])[] = [
	[kinds.common, kinds.protocol],
	[kinds.foundation],
	[kinds.capability],
	[kinds.feature],
	[kinds.adapter],
	[kinds.assembly, kinds.wiring, kinds.verification],
	[kinds.companion],
];

/** Kinds that never depend on a capability, though it sits below them. */
export const capabilityBlind: readonly Kind[] = [kinds.feature];

/** What a companion may depend on besides its own kind: a program outside the provider reads the wire and the rules, never the provider's parts. */
export const companionReach: readonly Kind[] = [kinds.common, kinds.protocol, kinds.foundation];

const levelOf = (kind: string) => kindOrder.findIndex((level) => level.some((k) => k === kind));

/** Whether a package of kind `from` may depend on one of kind `to`; never, where either is no kind. */
export function mayNeed(from: string, to: string): boolean {
	const [above, below] = [levelOf(from), levelOf(to)];
	if (above < 0 || below < 0 || below > above) return false;
	if (from === kinds.companion && to !== kinds.companion && !companionReach.some((k) => k === to))
		return false;
	return !(to === kinds.capability && capabilityBlind.some((k) => k === from));
}
