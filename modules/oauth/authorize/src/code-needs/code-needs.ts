import { clientAllowance } from "@mod/client-allowance";
import type { Client } from "@mod/clients";
import { challengeShape, codeGrantType, codes, openid } from "@mod/code-grant";
import { type TargetRule, targetRules } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import type { AuthorizationItems } from "@mod/sdk-core-wire";
import { type SenderBindings, senderBinding } from "@mod/sender-binding";

/** The binding a code's request asked for ahead (`sender-binding`'s word). */
export type AskedBinding = Extract<
	ReturnType<SenderBindings["requestedOf"]>,
	{ readonly kind: "requested" }
>["binding"];

/** What the code's needs are read over: the binding kinds, whether an ID token is made, the rule for the audience asked, the issuer. */
export interface CodeNeedsParts {
	readonly bindings: Pick<SenderBindings, "requestedOf">;
	/** Whether `code-grant` makes an ID token: without, an OpenID request is refused. */
	readonly idTokens: boolean;
	/** The rule for the audience asked (`grants`' `targetRules`): `resource` is read by it alone. */
	readonly targets: Pick<TargetRule, "target"> | undefined;
	/** `issuer`'s URL: a client's audience where its allowance names none. */
	readonly issuer: string;
}

/** The need a request failed, by its word; for `resource`, the rule's own description where it gave one. */
export type Unmet =
	| { readonly need: "grant" | "challenge" | "binding" | "scope" }
	| { readonly need: "resource"; readonly description?: string };
/** A need the start finds unmet: never the scope, which the finish alone reads (`allowedIssuance`). */
export type StartUnmet =
	| { readonly need: "grant" | "challenge" | "binding" }
	| { readonly need: "resource"; readonly description?: string };

/**
 * What a code needs of an authorization's request and its client, checked at the start before T is
 * made, and again at the finish before the session opens, so nothing a code needs fails once the
 * person tapped: the client allowed the code grant, an S256 challenge's shape, a binding asked for
 * ahead in its form, the resource within the client's audiences, the scope within its allowance;
 * an OpenID request only where an ID token is made. Each answers the need it found unmet, the
 * caller answering it in its own words.
 */
export function codeNeedsOver(p: CodeNeedsParts) {
	const bound = (items: AuthorizationItems): AskedBinding | undefined => {
		const asked = p.bindings.requestedOf((name) =>
			name === "dpop_jkt" ? items.dpop_jkt : undefined,
		);
		return asked.kind === "requested" ? asked.binding : undefined;
	};
	return {
		/** Whether a scope (its words, or as the request names it) asks `openid`. */
		asksOpenid: (scope: string | readonly string[]) =>
			(typeof scope === "string" ? scope.split(" ") : scope).includes(openid),
		/** Whether an OpenID request goes unmet: no ID token is made. */
		openidUnmet: (items: AuthorizationItems) =>
			items.scope.split(" ").includes(openid) && !p.idTokens,
		/** At the start, before T: the code grant, the resource by the one rule, the challenge's shape, the binding asked for ahead. */
		atStart(client: Client, items: AuthorizationItems): StartUnmet | undefined {
			if (!clientAllowance.allowsGrant(client, codeGrantType)) return { need: "grant" };
			const resource = items.resource;
			if (resource !== undefined) {
				if (!p.targets)
					return { need: "resource", description: "resource is read by no rule here" };
				const verdict = p.targets.target({
					param: (name) => (name === "resource" ? resource : undefined),
					audience: [],
					within: (audience) => clientAllowance.allowsAudience(client, audience, p.issuer),
				});
				if (verdict.kind === "error") return { need: "resource", description: verdict.description };
				if (verdict.audience.length !== 1 || verdict.audience[0] !== resource)
					return { need: "resource", description: "resource is not the audience asked" };
			}
			if (!challengeShape.test(items.code_challenge)) return { need: "challenge" };
			if (!bound(items)) return { need: "binding" };
			return undefined;
		},
		/**
		 * At the finish, before the session: the code grant, the challenge's shape, the scope and
		 * audience allowed, the resource within them, the binding asked for ahead. The rule for the
		 * audience asked is not read here: the start read it before T.
		 */
		atFinish(
			client: Client,
			items: AuthorizationItems,
		):
			| Unmet
			| {
					readonly scope: readonly string[];
					readonly audience: readonly string[];
					readonly binding: AskedBinding;
			  } {
			if (!clientAllowance.allowsGrant(client, codeGrantType)) return { need: "grant" };
			if (!challengeShape.test(items.code_challenge)) return { need: "challenge" };
			const allowed = clientAllowance.allowedIssuance(client, items.scope, p.issuer);
			if (allowed.kind === "error") return { need: "scope" };
			const resource = items.resource;
			if (resource !== undefined && !clientAllowance.allowsAudience(client, resource, p.issuer))
				return { need: "resource" };
			const binding = bound(items);
			if (!binding) return { need: "binding" };
			const audience = resource === undefined ? allowed.audience : [resource];
			return { scope: allowed.scope, audience, binding };
		},
	};
}
export type CodeNeeds = ReturnType<typeof codeNeedsOver>;

/** What the code's needs take from the composition. */
export const codeNeedsTakes = [targetRules, senderBinding, codes] as const;

/** The rules for the audience asked themselves (resource-indicators'), not the token endpoint's `targets`, so no endpoint need be composed. */
export const targetsIn = (c: Pick<BuildContext<unknown>, "collect">) => c.collect(targetRules);

/** The code's needs over the composition; of the rules, the one the module's boot allows. */
export async function codeNeedsIn(
	c: Pick<BuildContext<unknown>, "get" | "collect">,
	issuer: string,
): Promise<CodeNeeds> {
	const rules = await targetsIn(c);
	return codeNeedsOver({
		bindings: await c.get(senderBinding),
		idTokens: (await c.get(codes)).issuesIdTokens(),
		targets: rules[0],
		issuer,
	});
}
