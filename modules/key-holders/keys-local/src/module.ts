import { defineModule } from "@mod/kernel";
import { keyHolders } from "@mod/keys/holder";
import { promiseNames, stances } from "@mod/promises";
import { localHolder } from "./holder.ts";
import { section } from "./section.ts";

// Safe on many instances given the same keys on each.
export default defineModule({ name: "keys-local", replicaSafe: true, section, takes: [] }, (m) => [
	m.contribute(keyHolders).by(async (c) => {
		const holder = await localHolder(c.section);
		if ("refused" in holder) return c.refuseAll(holder.refused);
		return holder;
	}),
	m.contribute(stances).by(() => ({
		promise: promiseNames.coreContained,
		holds: false,
		by: "keys-local",
		reason:
			"its keys are in the Core's memory: a compromised Core takes them out and signs on after it is stopped, and no signing is counted outside it",
	})),
]);
