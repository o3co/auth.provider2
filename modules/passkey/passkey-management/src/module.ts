import { statementItems } from "@mod/approvals";
import { routes } from "@mod/http";
import { type BuildContext, contract, defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";
import { operationKinds } from "@mod/transparency";
import { continueStages, firstKeyCreations, signUpCreations } from "./contract.ts";
import { creationItems } from "./creation/creation.ts";
import { keyChangeKind } from "./key-change/key-change.ts";
import { keyingOf, keyingTakes } from "./keying/keying.ts";
import { possessionItems } from "./registration/registration.ts";
import { continueRoute, stagesOf } from "./routes/routes.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;

/** The routes of a key's registration after its creation, made once from its parts. */
const keying = contract<Awaited<ReturnType<typeof keyingOf>>>("passkey-management.keying");

export default defineModule(
	{
		name: "passkey-management",
		section,
		replicaSafe: true,
		takes: [continueStages, ...keyingTakes],
	},
	(m) => [
		// A key a live key's passkey-add approves is outside the new authorization's claim (P1):
		// it breaks none of it.
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "passkey-management",
		})),
		// A creation's items are its own to fill, every one sdk-core-wire's schema names.
		m.contribute(statementItems).by(() => creationItems),
		m.contribute(statementItems).by(() => possessionItems),
		// The key change's writer: passkeys' kind with this package's preimage record.
		m.contribute(operationKinds).by(() => keyChangeKind),
		m.provide(keying).by((c: Context) => keyingOf(c)),
		// `/continue`, each stage to the module that continues it; `register` is this package's own.
		m.contribute(continueStages).by(async (c) => (await c.get(keying)).registerStage),
		m.contribute(continueStages).by(async (c) => (await c.get(keying)).renameStage),
		m.contribute(continueStages).by(async (c) => (await c.get(keying)).deleteStage),
		m.contribute(routes).by(async (c: Context) =>
			continueRoute({
				stages: stagesOf(await c.collect(continueStages), (reason) =>
					c.refuse("passkey-management", reason),
				),
				window: { limit: c.section.requests, ms: c.section.window * 1000 },
				refused: (stage, reason) =>
					c.log.info("passkey-management.continue_refused", { stage, reason }),
			}),
		),
		m.contribute(routes).by(async (c) => (await c.get(keying)).keyFinish),
		m.contribute(routes).by(async (c) => (await c.get(keying)).approvalStart),
		m.contribute(routes).by(async (c) => (await c.get(keying)).approvalFinish),
		m.provide(signUpCreations).by(async (c) => (await c.get(keying)).signUp),
		m.provide(firstKeyCreations).by(async (c) => (await c.get(keying)).firstKey),
	],
);
