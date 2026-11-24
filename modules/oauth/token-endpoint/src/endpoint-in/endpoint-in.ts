import { setTimeout as sleep } from "node:timers/promises";
import { audit } from "@mod/audit";
import { clients } from "@mod/clients";
import { type Grant, sessionIssuances, targets } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import { clientBindings, senderBinding } from "@mod/sender-binding";
import { accessTokenIssuance, accessTokens, issuanceFencing } from "@mod/tokens";
import { transparency, transparencyLog } from "@mod/transparency";
import { bundling, evidenceOf } from "../bundle/bundle.ts";
import { tokenEndpoint } from "../route/endpoint.ts";

/** What `endpointIn` takes from the build context (its own `targets` aside, which the module provides). */
export const endpointTakes = [
	clients,
	accessTokens,
	accessTokenIssuance,
	issuanceFencing,
	sessionIssuances,
	senderBinding,
	clientBindings,
	audit,
	transparency,
	transparencyLog,
] as const;

/** How long the owner waits before each look again at its bundle's judgment: about 3 s in all. */
const lookAgainMs = (look: number) => Math.min(10 * 2 ** look, 200);
const looks = 18;

/** The endpoint's handler over the contracts the assembly gives, dispatching to the grants composed. */
export const endpointIn = async (c: BuildContext<unknown>, composed: readonly Grant[]) => {
	const issuance = await c.get(accessTokenIssuance);
	const checking = await c.get(accessTokens);
	const log = await c.get(transparencyLog);
	// Random, and counted on this instance besides, so no two of its ops share an id.
	let made = 0;
	const issueBundle = bundling({
		transparency: await c.get(transparency),
		digest: (preimage) => log.digest(preimage),
		issuance,
		fresh: () => `${Buffer.from(c.random.bytes(16)).toString("base64url")}.${++made}`,
		pause: (look) => sleep(lookAgainMs(look)),
		looks,
	});
	return tokenEndpoint({
		clients: await c.get(clients),
		issuing: (request, verified) => {
			const evidence = evidenceOf(request, verified);
			return {
				admits: issuance.admits,
				issue: (ask) => issueBundle({ ...ask, evidence }),
				revokeReferenced: checking.revokeReferenced,
			};
		},
		fencing: await c.get(issuanceFencing),
		told: await c.collect(sessionIssuances),
		bindings: await c.get(senderBinding),
		required: await c.get(clientBindings),
		grants: new Map(composed.map((g) => [g.grantType, g])),
		targets: await c.get(targets),
		audit: await c.get(audit),
	});
};
