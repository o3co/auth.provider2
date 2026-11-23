import { emptyState, type FlowState } from "@mod/authority-rules";
import { defineModule, type Refusal } from "@mod/kernel";
import {
	frameStore,
	type OperationKind,
	operationKinds,
	type StateOwner,
	stateOwners,
	transparency,
	transparencyLog,
} from "./contract.ts";
import { transparencyOver } from "./driver/driver.ts";
import { section } from "./section.ts";

/** What the registrations leave undone: a field of the state with no owner or two, a part with no place. */
function registrationRefusals(
	bound: readonly string[],
	kinds: readonly OperationKind[],
	owners: readonly StateOwner[],
): Refusal[] {
	const where = "transparency";
	const fields = Object.keys(emptyState) as (keyof FlowState)[];
	const byField = fields.map((field) => ({
		field,
		holders: owners.filter((o) => o.holds.includes(field)).map((o) => o.name),
	}));
	return [
		...byField
			.filter((f) => f.holders.length === 0)
			.map((f) => ({
				where,
				reason: `the state's ${f.field} has no owner, so a Step would lose it`,
			})),
		...byField
			.filter((f) => f.holders.length > 1)
			.map((f) => ({
				where,
				reason: `the state's ${f.field} is held by ${f.holders.join(" and ")}`,
			})),
		...[...kinds, ...owners].flatMap((r) =>
			r.parts
				.filter((part) => !bound.includes(part))
				.map((part) => ({
					where,
					reason: `${r.name} names part ${part}, which no place is bound to`,
				})),
		),
	];
}

// Holds nothing of its own: every frame is in the store, so it is safe on many instances.
export default defineModule(
	{
		name: "transparency",
		section,
		replicaSafe: true,
		takes: [frameStore, transparencyLog, operationKinds, stateOwners],
	},
	(m) => [
		m.provide(transparency).by(async (c) => {
			const frames = await c.get(frameStore);
			const kinds = await c.collect(operationKinds);
			const owners = await c.collect(stateOwners);
			const refused = registrationRefusals(frames.parts, kinds, owners);
			if (refused.length > 0) c.refuseAll(refused);
			const log = await c.get(transparencyLog);
			return transparencyOver({ frames, log, kinds, owners, leaseMs: c.section.lease });
		}),
	],
);
