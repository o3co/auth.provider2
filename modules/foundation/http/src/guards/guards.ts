import { deepFreeze, type Refusal } from "@mod/kernel";
import type {
	HttpRequest,
	HttpResponse,
	Policy,
	PolicyMark,
	PolicyRule,
	Route,
} from "../contract.ts";
import { brokenGuarantees } from "../guarantees/guarantees.ts";

/** A route with its guard: the policies it uses, in its order; the first that answers ends the request. */
export type GuardedRoute = Route & {
	readonly guard?: (request: HttpRequest) => Promise<HttpResponse | "pass">;
};

/** The routes guarded by their policies, or why boot is refused. */
export type GuardedRoutes =
	| { readonly kind: "guarded"; readonly routes: readonly GuardedRoute[] }
	| { readonly kind: "refused"; readonly refusals: readonly Refusal[] };

/** A policy a route uses: its rule, with the options the route gave it. */
interface Step {
	readonly rule: PolicyRule;
	readonly options: unknown;
}

/** The guard applying steps in their order; the first that answers ends the request. */
const guardOf =
	(steps: readonly Step[]) =>
	async (request: HttpRequest): Promise<HttpResponse | "pass"> => {
		for (const { rule, options } of steps) {
			const answer = await rule.apply(request, options);
			if (answer !== "pass") return answer;
		}
		return "pass";
	};

const where = (route: Route) => `http.routes:${route.method} ${route.path}`;

/**
 * The routes guarded by the rules of the policies they use, matched by value (never label), each with a
 * frozen copy of what it uses; refused when a policy has two rules, a route uses a policy with none, or a
 * route breaks what it declares against the marks, in that order.
 */
export function guardedRoutes(
	routes: readonly Route[],
	rules: readonly PolicyRule[],
	marks: readonly PolicyMark[],
): GuardedRoutes {
	const ruleOf = new Map<Policy<unknown>, PolicyRule>(rules.map((rule) => [rule.policy, rule]));
	const twice = rules.find((rule, at) => rules.findIndex((r) => r.policy === rule.policy) !== at);
	if (twice) {
		const reason = `more than one rule for a policy: ${twice.policy.label}`;
		return { kind: "refused", refusals: [{ where: "http.policies", reason }] };
	}
	const missing = routes.flatMap((route) =>
		(route.uses ?? [])
			.filter((use) => !ruleOf.has(use.policy))
			.map((use) => ({
				where: where(route),
				reason: `uses a policy no module applies: ${use.policy.label}`,
			})),
	);
	if (missing.length > 0) return { kind: "refused", refusals: missing };
	const broken = brokenGuarantees(routes, marks);
	if (broken.length > 0) {
		const refusals = broken.map(({ route, reason }) => ({ where: where(route), reason }));
		return { kind: "refused", refusals };
	}
	return {
		kind: "guarded",
		routes: routes.map((route) => {
			const steps = Object.freeze(
				(route.uses ?? []).map((use) =>
					Object.freeze({
						rule: ruleOf.get(use.policy) as PolicyRule,
						options: deepFreeze(structuredClone(use.options)),
					}),
				),
			);
			if (steps.length === 0) return route;
			return Object.freeze({ ...route, guard: guardOf(steps) });
		}),
	};
}
