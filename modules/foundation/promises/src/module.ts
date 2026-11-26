import { deepFreeze, defineModule } from "@mod/kernel";
import { z } from "zod";
import {
	type Breaking,
	evidence,
	evidenceKinds,
	type PromiseJudgment,
	type PromiseName,
	promiseNames,
	promises,
	type Stance,
	type Strength,
	stances,
	trustedNames,
} from "./contract.ts";

const names = Object.values(promiseNames) as [PromiseName, ...PromiseName[]];

const whole = z.number().int().min(1);
const word = z.string().regex(/\S/);
const guesses = z.strictObject({ count: whole, windowMs: whole });
/** A declared evidence kind as the contract types it, read at run time too: a module's value may stray. */
const kindShape = z.strictObject({
	kind: word,
	by: word,
	trusts: z
		.array(z.enum(Object.values(trustedNames) as [string, ...string[]]))
		.min(1)
		.refine((all) => new Set(all).size === all.length, "a word named twice"),
	strength: z.discriminatedUnion("kind", [
		z.strictObject({ kind: z.literal("guesses"), guesses }),
		z.strictObject({ kind: z.literal("secret"), bits: whole, lifetimeMs: whole }),
		z.strictObject({
			kind: z.literal("code"),
			digits: whole,
			windows: z.number().int().min(0),
			guesses,
		}),
		z.strictObject({ kind: z.literal("key"), userVerified: z.boolean() }),
		z.strictObject({
			kind: z.literal("issuer"),
			issuer: word,
			acr: z.array(word).min(1).optional(),
		}),
	]),
	past: z.literal(true).optional(),
	alone: z.literal(true).optional(),
});

/** A strength as one line says it, its values only, in a fixed order. */
function strengthLine(strength: Strength): string {
	switch (strength.kind) {
		case "guesses":
			return `guesses ${strength.guesses.count} per ${strength.guesses.windowMs} ms on each instance`;
		case "secret":
			return `secret of ${strength.bits} bits, living ${strength.lifetimeMs} ms, used once`;
		case "code":
			return `code of ${strength.digits} digits, ${strength.windows} windows either side, guesses ${strength.guesses.count} per ${strength.guesses.windowMs} ms on each instance`;
		case "key":
			return `key${strength.userVerified ? " verifying its user" : ""}`;
		case "issuer":
			return `issuer ${strength.issuer}${strength.acr ? ` asked acr ${strength.acr.join(" ")}` : ""}`;
	}
}

const section = z.strictObject({
	required: z
		.array(z.enum(names))
		.prefault([])
		.describe("The promises this deployment requires: boot is refused where one does not hold."),
});

/** What no promise's judgment checks. */
const uncheckedByAll = "operator's conditions; receivers' duties";

/** What one promise's judgment does not see, past what none checks. */
const uncheckedFor: Partial<Record<PromiseName, string>> = {
	[promiseNames.noClientSubjectToken]: "issuance not through the token endpoint",
	[promiseNames.clientToken]: "issuance not through the token endpoint",
};

const unchecked = (promise: PromiseName) =>
	[uncheckedByAll, uncheckedFor[promise]].filter((part) => part !== undefined).join("; ");

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
	{ name: "promises", section, replicaSafe: true, takes: [stances, evidenceKinds] },
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
						unchecked: unchecked(one.promise),
						...(one.breaking.length === 0 ? {} : { breaking: said(one.breaking) }),
					};
					if (one.held) c.log.info("promises.judged", fields);
					else c.log.warn("promises.judged", fields);
				}
			});
			return { judgment: () => judgment };
		}),
		m.provide(evidence).by(async (c) => {
			const declared = await c.collect(evidenceKinds);
			// Each kind refused where the kernel names a keyed contribution, at the first part off the shape.
			const loose = declared.flatMap((k) => {
				const read = kindShape.safeParse(k);
				const at = read.error?.issues[0]?.path.join(".");
				return read.success
					? []
					: [
							{
								where: `${evidenceKinds.label}:${String(k.kind)}`,
								reason: `not of promises' shape at ${at || "the kind"}`,
							},
						];
			});
			if (loose.length > 0) c.refuseAll(loose);
			// By name in code units, so every host lists them alike. Keyed, so no name twice.
			const kinds = deepFreeze(
				declared.toSorted((a, b) => (a.kind < b.kind ? -1 : 1)).map((k) => structuredClone(k)),
			);
			c.onStart(() => {
				for (const k of kinds) {
					const fields = {
						kind: k.kind,
						by: k.by,
						trusts: k.trusts.join(" "),
						strength: strengthLine(k.strength),
						...(k.past ? { past: true } : {}),
						...(k.alone ? { alone: true } : {}),
					};
					c.log.info("promises.evidence", fields);
				}
			});
			return { kinds: () => kinds };
		}),
	],
);
