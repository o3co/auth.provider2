import { families } from "@mod/code-grant";
import { erasers } from "@mod/erasure-extensions";
import { grants } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";
import { revocableKinds } from "@mod/token-revocation";
import { delegation, familyRecords } from "./contract.ts";
import { familyEraser, portsRefused } from "./erasure/erasure.ts";
import { foundingIn, foundingTakes } from "./family/family.ts";
import { grantIn, grantTakes } from "./grant/grant.ts";
import { section } from "./section.ts";

const takes = [...foundingTakes, ...grantTakes];

// Safe on many instances: every record changes from what it holds, and a family is founded once.
export default defineModule({ name: "refresh", replicaSafe: true, section, takes }, (m) => [
	m.provide(delegation).by((c) => ({ lifetimeMs: c.section.lifetime * 1000 })),
	m.contribute(families).by(async (c) => {
		const refused = portsRefused(await c.get(familyRecords));
		if (refused) return c.refuse("refresh", refused);
		return foundingIn(c, c.section.lifetime * 1000);
	}),
	m.contribute(grants).by(async (c) => (await grantIn(c, c.section.lifetime * 1000)).grant),
	m
		.contribute(revocableKinds)
		.by(async (c) => (await grantIn(c, c.section.lifetime * 1000)).revocable),
	// Its build takes only its store, collecting no probes: the erasure gate collects erasers.
	m.contribute(erasers).by(async (c) => familyEraser(await c.get(familyRecords))),
	// It takes `keys` and `approvals`, which ask where their takers stand: a family rests on a passkey's approval.
	m.contribute(stances).by(() => ({
		promise: promiseNames.newAuthorization,
		holds: true,
		by: "refresh",
	})),
]);
