import { families } from "@mod/code-grant";
import { erasers } from "@mod/erasure-extensions";
import { grants, sessionIssuances } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { passkeyRemovals, passkeys } from "@mod/passkeys";
import { promiseNames, stances } from "@mod/promises";
import { revocableKinds } from "@mod/token-revocation";
import { delegation, familyRecords } from "./contract.ts";
import { familyEraser, portsRefused } from "./erasure/erasure.ts";
import { foundingIn, foundingTakes } from "./family/family.ts";
import { grantIn, grantTakes } from "./grant/grant.ts";
import { heldBy, removalOver, rootedOver } from "./rooted/rooted.ts";
import { section } from "./section.ts";

const takes = [...foundingTakes, ...grantTakes, sessionIssuances];

// Safe on many instances: every record changes from what it holds, and a family is founded once.
export default defineModule({ name: "refresh", replicaSafe: true, section, takes }, (m) => [
	m.provide(delegation).by((c) => ({ lifetimeMs: c.section.lifetime * 1000 })),
	m.contribute(families).by(async (c) => {
		const refused = portsRefused(await c.get(familyRecords));
		if (refused) return c.refuse("refresh", refused);
		return foundingIn(c, c.section.lifetime * 1000);
	}),
	m.contribute(grants).by(async (c) => {
		// Its tokens are issued from their family's session: unrecorded, a logout could not end them.
		if ((await c.collect(sessionIssuances)).length === 0)
			return c.refuse(
				"refresh",
				"its tokens must be recorded to their session, so that a logout ends them",
			);
		return (await grantIn(c, c.section.lifetime * 1000)).grant;
	}),
	m
		.contribute(revocableKinds)
		.by(async (c) => (await grantIn(c, c.section.lifetime * 1000)).revocable),
	// Its build takes only its store, collecting no probes: the erasure gate collects erasers.
	m.contribute(erasers).by(async (c) => familyEraser(await c.get(familyRecords))),
	// A passkey removed, or a subject's keys emptied, ends the families rooted in it (Q46).
	m.contribute(passkeyRemovals).by(async (c) =>
		removalOver(
			rootedOver({
				records: await c.get(familyRecords),
				lifetimeMs: c.section.lifetime * 1000,
				now: c.clock.now,
				held: heldBy(await c.get(passkeys)),
			}).rooted,
		),
	),
	// It takes `keys` and `approvals`, which ask where their takers stand: a family rests on a passkey's approval.
	m.contribute(stances).by(() => ({
		promise: promiseNames.newAuthorization,
		holds: true,
		by: "refresh",
	})),
]);
