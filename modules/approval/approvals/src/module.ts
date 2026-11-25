import { setTimeout as sleep } from "node:timers/promises";
import { issuer } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { keys } from "@mod/keys";
import { keyList, passkeys } from "@mod/passkeys";
import { promiseNames, stances } from "@mod/promises";
import { rateLimit } from "@mod/rate-limit";
import { operationKinds, stateOwners, transparency, transparencyLog } from "@mod/transparency";
import { approvalKind, approvalsOwner, completionsOver } from "./completion/completion.ts";
import { keyChangeCompletionsOver } from "./completion/key-change.ts";
import { beyondLimits } from "./completion/padded.ts";
import { passkeyAddCompletionsOver } from "./completion/passkey-add.ts";
import { passkeyManageCompletionsOver } from "./completion/passkey-manage.ts";
import { continuationsOver } from "./continuation/continuation.ts";
import { approvalStore, approvals, statementItems } from "./contract.ts";
import { type Settings, section } from "./section.ts";
import { declaredOf, statementsOver } from "./statement/statement.ts";

type Context = BuildContext<Settings>;

const lookAgainMs = (look: number) => Math.min(10 * 2 ** look, 200);

// Holds nothing of its own: statements are in its store, its part of each flow in the frames' store.
export default defineModule(
	{
		name: "approvals",
		section,
		replicaSafe: true,
		takes: [
			keys,
			passkeys,
			keyList,
			approvalStore,
			rateLimit,
			issuer,
			transparency,
			transparencyLog,
			statementItems,
		],
	},
	(m) => [
		m.contribute(operationKinds).by(() => approvalKind),
		m.contribute(stateOwners).by(() => approvalsOwner),
		// An approval is used only by an assertion that verified its user, whatever passkeys' section says.
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "approvals",
		})),
		m.provide(approvals).by(async (c: Context) => {
			const store = await c.get(approvalStore);
			const signer = await c.get(keys);
			const iss = (await c.get(issuer)).url;
			// A completion these settings would not fit is refused at boot, never to one person alone.
			const beyond = beyondLimits(iss, signer.coreRings());
			if (beyond) c.refuse("approvals", beyond);
			const now = c.clock.now;
			const statements = statementsOver({
				keys: signer,
				passkeys: await c.get(passkeys),
				store,
				limit: await c.get(rateLimit),
				window: { limit: c.section["issue-limit"], ms: c.section["issue-window"] },
				total: c.section["issue-total"],
				issuer: iss,
				declared: declaredOf(await c.collect(statementItems), (reason) =>
					c.refuse("approvals", reason),
				),
				lifetimeS: c.section["statement-lifetime"],
				maxConcurrent: c.section["max-concurrent"],
				now,
				token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
			});
			return {
				...statements,
				...continuationsOver({
					keys: signer,
					list: await c.get(keyList),
					store,
					now,
					token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
				}),
				complete: completionsOver({
					transparency: await c.get(transparency),
					digest: (await c.get(transparencyLog)).digest,
					keys: signer,
					store,
					issuer: iss,
					now,
					pause: (look) => sleep(lookAgainMs(look)),
					looks: 18,
				}),
				completeKeyChange: keyChangeCompletionsOver({ keys: signer, store, issuer: iss, now }),
				completePasskeyAdd: passkeyAddCompletionsOver({ keys: signer, store, issuer: iss, now }),
				completePasskeyManage: passkeyManageCompletionsOver({
					keys: signer,
					store,
					list: await c.get(keyList),
					issuer: iss,
					now,
				}),
			};
		}),
	],
);
