import { defineModule } from "@mod/kernel";
import { keyChangePart, type keyChangePartNeeds } from "@mod/passkey-management";
import { type Guarantee, type Space, spaces } from "@mod/store";
import { frameParts } from "@mod/transparency-frames";

/** Each need passkey-management states for its part, as the guarantee its space declares: a need left out fails the type check. */
const guaranteeFor: Record<keyof typeof keyChangePartNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};

/** passkey-management's part of each subject's flow, written by the flow's one write, as the frames are. */
const flows: Space = {
	name: "passkey-management-store.flows",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{ name: "passkey-management-store", replicaSafe: true, takes: [] },
	(m) => [
		m.contribute(spaces).by(() => flows),
		m.contribute(frameParts).by(() => ({ name: keyChangePart, space: flows })),
	],
);
