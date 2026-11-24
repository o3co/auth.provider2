import { defineModule } from "@mod/kernel";
import { passkeyGenerations, passkeys } from "@mod/passkeys";
import { promiseNames, stances } from "@mod/promises";
import { transparency } from "@mod/transparency";
import { passkeyReset } from "./contract.ts";
import { resetOver } from "./reset.ts";

// Holds nothing of its own: the boundary is the log's, the keys passkeys'.
export default defineModule(
	{
		name: "passkey-reset",
		replicaSafe: true,
		takes: [transparency, passkeys, passkeyGenerations],
	},
	(m) => [
		// O1: the reset's path clears a subject's keys, so a new login rests on who calls it.
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "passkey-reset",
			reason:
				"held where its caller is the embedder's recovery procedure, on the Core's side alone and never reached from the Front: the operator's condition",
		})),
		m.provide(passkeyReset).by(async (c) =>
			resetOver({
				transparency: await c.get(transparency),
				passkeys: await c.get(passkeys),
				generations: await c.get(passkeyGenerations),
			}),
		),
	],
);
