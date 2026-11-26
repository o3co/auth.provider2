import { defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";
import { operationKinds, stateOwners } from "@mod/transparency";
import {
	approvalKind,
	approvalsOwner,
	completionOf,
	completionTakes,
} from "./completion/completion.ts";
import { continuationOf, continuationTakes } from "./continuation/continuation.ts";
import { approvalStore, approvals } from "./contract.ts";
import {
	keyChangeCompletionOf,
	keyChangeCompletionTakes,
} from "./key-change-completion/key-change.ts";
import {
	completionLimitsChecked,
	passkeyCompletionOf,
	passkeyCompletionTakes,
} from "./passkey-completion/passkey-completion.ts";
import { section } from "./section.ts";
import { statementOf, statementTakes } from "./statement/statement.ts";

// Holds nothing of its own: statements are in its store, its part of each flow in the frames' store.
export default defineModule(
	{
		name: "approvals",
		section,
		replicaSafe: true,
		takes: [
			...new Set([
				...statementTakes,
				...continuationTakes,
				...completionTakes,
				...keyChangeCompletionTakes,
				...passkeyCompletionTakes,
			]),
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
		// Each internal module makes its part of the contract. Its parts are asked in this order, so a boot
		// that fails twice reports alike: the store, the completion limits (the issuer, the ring), the
		// statements (`passkeys`, `rate-limit`, the declared items), the continuations (the keys' list),
		// the authorization's completion (`transparency`), then what is asked already.
		m.provide(approvals).by(async (c) => {
			await c.get(approvalStore);
			await completionLimitsChecked(c);
			const statement = await statementOf(c);
			const continuation = await continuationOf(c);
			const completion = await completionOf(c);
			return {
				...statement,
				...continuation,
				...completion,
				...(await keyChangeCompletionOf(c)),
				...(await passkeyCompletionOf(c)),
			};
		}),
	],
);
