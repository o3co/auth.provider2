import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { acr, amrSources } from "./contract.ts";
import { section } from "./section.ts";

/** A name an object puts first, ascending, whatever order it was written in: one read as an array index. */
const indexLike = (name: string) => /^(?:0|[1-9]\d*)$/.test(name) && Number(name) < 2 ** 32 - 1;

export default defineModule(
	{ name: "acr", replicaSafe: true, section, takes: [amrSources] },
	(m) => [
		m.provide(acr).by(async (c) => {
			const table = c.section.values;
			// A set is met by the declared ways together, as one approval may go on through continuation steps.
			const provable = new Set((await c.collect(amrSources)).flatMap((source) => source.amr));
			const unmet = Object.entries(table)
				.filter(([, sets]) => !sets.some((set) => set.every((amr) => provable.has(amr))))
				.map(([name]) => ({
					where: `acr.values.${name}`,
					reason: "no declared way of logging in can meet it",
				}));
			if (unmet.length > 0) return c.refuseAll(unmet);
			// The configuration is read as an object, which puts index-like names first: their written order is lost.
			const written = Object.keys(table);
			const reordered = written.filter(indexLike);
			if (written.length > 1 && reordered.length > 0) {
				c.log.warn("acr.values_order", { names: reordered.join(", ") });
			}
			/** The first of these acr, in their order, whose one set the amr hold whole. */
			const firstMet = (names: readonly string[], amr: readonly string[]) => {
				const held = new Set(amr);
				const meets = (name: string) =>
					Object.hasOwn(table, name) && table[name]?.some((set) => set.every((a) => held.has(a)));
				return names.find(meets);
			};
			return {
				known: (asked) => asked.split(" ").filter((name) => Object.hasOwn(table, name)),
				met: firstMet,
				current: (amr) => firstMet(written, amr),
			};
		}),
		m.contribute(metadata).by((c) => {
			const offered = Object.keys(c.section.values);
			return { name: "acr_values_supported", value: offered.length > 0 ? offered : undefined };
		}),
	],
);
