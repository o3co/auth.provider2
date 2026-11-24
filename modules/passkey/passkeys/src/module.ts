import { type BuildContext, contract, defineModule } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { promiseNames, stances } from "@mod/promises";
import { frameStore, operationKinds, stateOwners, transparency } from "@mod/transparency";
import { ceremonies } from "@mod/webauthn";
import {
	passkeyClearing,
	passkeyRemovals,
	passkeyStore,
	passkeys,
	passkeyWitnessing,
	registrations,
} from "./contract.ts";
import { type KeptParts, keptOver } from "./kept.ts";
import { keyChanges, keysOwner } from "./records.ts";
import { registeringOver } from "./registering.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;

/** The one witnessing contributed, if any; two, or a witness nothing asks, refuse boot. */
async function witnessingOf(c: Context) {
	const [witnessing, ...others] = await c.collect(passkeyWitnessing);
	if (others.length > 0)
		return c.refuse("passkeys", "more than one passkey witnessing is contributed");
	// A witness nothing asks would leave a lost store to read as holding none.
	if (!witnessing && (await c.collect(passkeyWitnesses)).length > 0)
		return c.refuse("passkeys", "a passkey witness is composed without passkey witnessing");
	return witnessing;
}

/** The parts both faces read the keys with, made once. */
const kept = contract<KeptParts>("passkeys.kept");
/** Registering and clearing, made once over the frame and the key change's kind. */
const registering = contract<ReturnType<typeof registeringOver>>("passkeys.registering");

// Holds nothing of its own: the keys are in the frames' store, the credentials in its own.
export default defineModule(
	{
		name: "passkeys",
		section,
		replicaSafe: true,
		takes: [
			frameStore,
			transparency,
			passkeyStore,
			ceremonies,
			operationKinds,
			passkeyWitnesses,
			passkeyWitnessing,
			passkeyRemovals,
		],
	},
	(m) => [
		m.contribute(stateOwners).by(() => keysOwner),
		// A new login rests on the user's passkey verifying its user: weakened, the promise breaks.
		m.contribute(stances).by((c: Context) =>
			c.section["user-verification"] === "required"
				? { promise: promiseNames.newAuthorization, holds: true, by: "passkeys" }
				: {
						promise: promiseNames.newAuthorization,
						holds: false,
						by: "passkeys",
						setting: "passkeys.user-verification",
						reason: "an assertion need not show the authenticator verified its user",
					},
		),
		m.provide(kept).by(async (c) => ({
			frames: await c.get(frameStore),
			store: await c.get(passkeyStore),
			ceremonies: await c.get(ceremonies),
			verification: c.section["user-verification"],
		})),
		m.provide(passkeys).by(async (c) =>
			keptOver({
				...(await c.get(kept)),
				witnessing: await witnessingOf(c),
				removals: await c.collect(passkeyRemovals),
			}),
		),
		m.provide(registering).by(async (c) => {
			const kinds = await c.collect(operationKinds);
			if (!kinds.some((k) => k.name === keyChanges.name))
				c.refuse("passkeys", `no writer registers the key change's kind ${keyChanges.name}`);
			return registeringOver({
				...(await c.get(kept)),
				transparency: await c.get(transparency),
				witnessing: await witnessingOf(c),
				now: c.clock.now,
				token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
				lifetimeMs: c.section["pending-lifetime"],
				max: c.section["max-credentials"],
			});
		}),
		m.provide(registrations).by(async (c) => {
			const { reserve, verifyPending, commit, cancel, remove } = await c.get(registering);
			return { reserve, verifyPending, commit, cancel, remove };
		}),
		m.provide(passkeyClearing).by(async (c) => ({ clear: (await c.get(registering)).clear })),
	],
);
