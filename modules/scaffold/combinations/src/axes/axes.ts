import type { Declared, Package } from "../declared.ts";

/** The axis owner a package adapts to or replaces. */
export const axisOf = (p: Package | undefined) => p?.replaces ?? p?.adapts;

/** Each axis's adapters, by owner; the default is the one declaring it, or else the only one (of the workspace's, where it has any), never one declaring itself never the default. */
export function axesIn(declared: Declared) {
	const adapters = new Map<string, Package[]>();
	for (const p of declared.packages.values()) {
		const owner = axisOf(p);
		if (owner !== undefined) adapters.set(owner, [...(adapters.get(owner) ?? []), p]);
	}
	const defaultOf = (owner: string) => {
		const of = (adapters.get(owner) ?? []).filter((p) => !p.neverDefault);
		// An adapter declared outside never takes the place of the workspace's only one.
		const ours = of.filter((p) => !p.outside);
		const only = ours.length > 0 ? ours : of;
		return (of.find((p) => p.default) ?? (only.length === 1 ? only[0] : undefined))?.name;
	};
	/** The adapter declared the default that replaces an owner: it composes in the owner's place, a module or not. */
	const replacingOf = (owner: string) =>
		(adapters.get(owner) ?? []).find((p) => p.default && p.replaces === owner)?.name;
	return { adapters, defaultOf, replacingOf };
}
