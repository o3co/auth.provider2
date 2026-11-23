import { defineModule } from "@mod/kernel";
import { keyHolders } from "@mod/keys/holder";
import { kmsHolder } from "./holder.ts";
import type { Kms } from "./kms.ts";
import { type Section, section } from "./section.ts";

/** The adapter, its calls of KMS made through the client `kmsFor` gives for the section. */
export function keysKms(kmsFor: (s: Section) => Kms) {
	// Safe on many instances: each holds only the public halves it read, and KMS signs for all.
	return defineModule({ name: "keys-kms", replicaSafe: true, section, takes: [] }, (m) => [
		m.contribute(keyHolders).by(async (c) => {
			const kms = kmsFor(c.section);
			c.onStop(() => kms.destroy());
			const holder = await kmsHolder(c.section, kms);
			if ("refused" in holder) return c.refuseAll(holder.refused);
			return holder;
		}),
	]);
}
