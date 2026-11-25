import { canonicalText } from "@mod/sdk-core-wire";
import type { Json, StateOwner } from "@mod/transparency";

/** refresh's part of a subject's flow, named after it as each owner's is: the state's families, which its store wiring binds to a space. */
export const familiesPart = "refresh";
const stateRecord = { part: familiesPart, name: "state" } as const;

type FlowState = Parameters<StateOwner["write"]>[0];
type Held = Pick<FlowState, "families">;
const heldOf = (held: Json | undefined): Held => ({
	families: ((held ?? {}) as Partial<Held>).families ?? {},
});

/** The owner of the flow state's families: refresh's, as a family is its delegation (Axiom 1). */
export const familiesOwner: StateOwner = {
	name: "refresh",
	holds: ["families"],
	parts: [familiesPart],
	records: () => [stateRecord],
	read: ([held]) => heldOf(held),
	write: (state, [held]) => {
		const next: Held = { families: state.families };
		return [
			canonicalText(next) === canonicalText(heldOf(held))
				? undefined
				: { value: next as unknown as Json },
		];
	},
};
