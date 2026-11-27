import { axesIn, axisOf } from "./axes/axes.ts";
import type { Declared } from "./declared.ts";

/** The modules given, then the wirings and the bridges `admitted` lets come, each once, in turn until nothing more comes. */
function closure(
	declared: Declared,
	modules: readonly string[],
	admitted: (bridge: string, all: readonly string[]) => boolean,
) {
	const all = [...modules];
	const add = (name: string) => {
		if (!all.includes(name)) all.push(name);
	};
	for (let size = -1; size !== all.length; ) {
		size = all.length;
		for (const name of all) for (const wiring of declared.wirings.get(name) ?? []) add(wiring);
		for (const { joins, bridge } of declared.bridges) {
			if (joins.every((m) => all.includes(m)) && admitted(bridge, all)) add(bridge);
		}
	}
	return all;
}

/**
 * The modules given, then the wirings and bridges declared for them, each once and in the order
 * first named. A bridge that is an adapter is not one the caller `excluded`, and comes only where no
 * other adapter of its axis is among the modules; where its axis's default joins too, only that
 * default, or one `chosen` for the axis, comes as a bridge, whatever the names.
 */
export function completedWith(
	declared: Declared,
	modules: readonly string[],
	excluded: ReadonlySet<string> = new Set(),
	chosen: ReadonlySet<string> = new Set(),
): string[] {
	const { adapters, defaultOf } = axesIn(declared);
	const bridges = new Set(declared.bridges.map((b) => b.bridge));
	const waiting = new Set(
		[...adapters].flatMap(([owner, of]) => {
			const first = defaultOf(owner);
			return first !== undefined && bridges.has(first)
				? of.filter((a) => a.name !== first && !chosen.has(a.name)).map((a) => a.name)
				: [];
		}),
	);
	return closure(declared, modules, (bridge, all) => {
		if (excluded.has(bridge) || waiting.has(bridge)) return false;
		const owner = axisOf(declared.packages.get(bridge));
		const others = (adapters.get(owner ?? "") ?? []).filter((a) => a.name !== bridge);
		return !others.some((a) => all.includes(a.name));
	});
}
