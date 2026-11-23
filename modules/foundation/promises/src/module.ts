import { defineModule } from "@mod/kernel";
import { z } from "zod";
import {
	type Breaking,
	type PromiseJudgment,
	type PromiseName,
	promiseNames,
	promises,
	type Stance,
	stances,
} from "./contract.ts";

const names = Object.values(promiseNames) as [PromiseName, ...PromiseName[]];

const section = z.strictObject({
	required: z
		.array(z.enum(names))
		.prefault([])
		.describe("The promises this deployment requires: boot is refused where one does not hold."),
});

/** One promise judged from every stance: held where one holds it and none breaks it. */
function judge(promise: PromiseName, all: readonly Stance[]): PromiseJudgment {
	const on = all.filter((s) => s.promise === promise);
	const breaking: Breaking[] = on
		.filter((s) => !s.holds)
		.map(({ by, setting, reason }) => ({
			by,
			...(setting === undefined ? {} : { setting }),
			...(reason === undefined ? {} : { reason }),
		}));
	const held = breaking.length === 0 && on.some((s) => s.holds);
	return Object.freeze({ promise, held, basis: "declared", breaking: Object.freeze(breaking) });
}

/** What breaks a promise, as one line: each module, its setting and its reason. */
const said = (breaking: readonly Breaking[]) =>
	breaking
		.map((b) => [b.by, b.setting, b.reason].filter((part) => part !== undefined).join(": "))
		.join("; ");

export default defineModule(
	{ name: "promises", section, replicaSafe: true, takes: [stances] },
	(m) => [
		m.provide(promises).by(async (c) => {
			const all = await c.collect(stances);
			const judgment = Object.freeze(names.map((name) => judge(name, all)));
			const refused = c.section.required.flatMap((name, i) => {
				const one = judgment.find((j) => j.promise === name);
				return one?.held
					? []
					: [
							{
								where: `promises.required.${i}`,
								reason: `${name} does not hold: ${said(one?.breaking ?? [])}`,
							},
						];
			});
			if (refused.length > 0) c.refuseAll(refused);
			c.onStart(() => {
				for (const one of judgment) {
					const fields = {
						promise: one.promise,
						held: one.held,
						basis: one.basis,
						unchecked: "operator's conditions; receivers' duties",
						...(one.breaking.length === 0 ? {} : { breaking: said(one.breaking) }),
					};
					if (one.held) c.log.info("promises.judged", fields);
					else c.log.warn("promises.judged", fields);
				}
			});
			return { judgment: () => judgment };
		}),
	],
);
