import { approvals } from "@mod/approvals";
import { signUpOffers, withoutPasskey } from "@mod/authorize";
import { type BuildContext, defineModule } from "@mod/kernel";
import { continueStages, signUpCreations } from "@mod/passkey-management";
import { promiseNames, stances } from "@mod/promises";
import { rateLimit } from "@mod/rate-limit";
import { users } from "@mod/users";
import { type Settings, section } from "./section.ts";
import { signUpStage, signUpsOver } from "./sign-up.ts";

type Context = BuildContext<Settings>;

/** A T's sign-up as a build composes it: refused where the ledger makes no identifierless subjects. */
async function signUpsIn(c: Context) {
	const make = (await c.get(users)).createIdentifierless;
	if (!make)
		return c.refuse("sign-up", "the users' ledger makes no subjects without an identifier");
	return signUpsOver({
		approvals: await c.get(approvals),
		createIdentifierless: make,
		creations: await c.get(signUpCreations),
		limit: await c.get(rateLimit),
		window: { limit: c.section["per-source"], ms: c.section.window * 1000 },
		perClient: c.section["per-client"],
		total: c.section.total,
		limited: (count, client) =>
			c.log.info("sign-up.limited", client === undefined ? { count } : { count, client }),
	});
}

// Holds nothing of its own: the subject is the ledger's, T's sign-up approvals', its creation the key
// management package's.
export default defineModule(
	{
		name: "sign-up",
		section,
		replicaSafe: true,
		takes: [approvals, users, signUpCreations, rateLimit],
	},
	(m) => [
		m.contribute(continueStages).by(async (c: Context) => signUpStage(await signUpsIn(c))),
		m.contribute(signUpOffers).by(() => ({ by: "sign-up" })),
		// Composed, a sign-up is allowed for every client's authorization (§4.3): no client's own word.
		m.contribute(withoutPasskey).by(() => ({ allows: async () => true })),
		// A sign-up makes a new subject and its first key, under a T its screen signed, and reaches no
		// subject that was there before: T is used by the credential this sign-up registered alone
		// (approvals), so no person's login comes of it that was not theirs, and it breaks no part of
		// the new authorization's claim (P1).
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "sign-up",
		})),
	],
);
