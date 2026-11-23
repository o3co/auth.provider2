import { extensionPoint } from "@mod/kernel";
import type { HttpRequest, HttpResponse, Method } from "../contract.ts";

/** A rule a route can ask the server to apply before its handler. Its owner makes it; it is unique as a value. */
export interface Policy<O = undefined> {
	readonly kind: "policy";
	readonly label: string;
	readonly __options?: O;
}

export function policy<O = undefined>(label: string): Policy<O> {
	return Object.freeze({ kind: "policy", label });
}

/** A route's use of a policy, with what the route gives it: plain data, copied and frozen at boot. */
export interface PolicyUse {
	readonly policy: Policy<unknown>;
	readonly options: unknown;
}

export function use<O>(policy: Policy<O>, ...options: O extends undefined ? [] : [O]): PolicyUse {
	return Object.freeze({ policy: policy as Policy<unknown>, options: options[0] });
}

/** How a policy applies: pass the request on to the next, or answer it. Throws Unavailable when it cannot tell. */
export interface PolicyRule {
	readonly policy: Policy<unknown>;
	apply(
		request: HttpRequest,
		options: unknown,
	): "pass" | HttpResponse | Promise<"pass" | HttpResponse>;
}

export function applying<O>(
	policy: Policy<O>,
	apply: (
		request: HttpRequest,
		options: O,
	) => "pass" | HttpResponse | Promise<"pass" | HttpResponse>,
): PolicyRule {
	return { policy: policy as Policy<unknown>, apply: apply as PolicyRule["apply"] };
}

/** The rules of the policies, one per policy; a server matches them to the policies routes use by value. */
export const policies = extensionPoint<PolicyRule>("http.policies", {
	multiplicity: "many",
});

/** What a route's policies keep: `own-site`, no other site's request reaches the handler; `per-source`, a source over its count does not. */
export type RouteGuarantee = "own-site" | "per-source";

/** A policy owner's own claim that these policies keep a guarantee, each for the methods named; a claim, never a proof. */
export interface PolicyMark {
	readonly guarantee: RouteGuarantee;
	readonly policies: readonly {
		readonly policy: Policy<unknown>;
		readonly methods: readonly Method[];
	}[];
}

/** One mark per guarantee, matched to the policies a route uses by value. */
export const marks = extensionPoint<PolicyMark>("http.marks", {
	multiplicity: "keyed",
	keyOf: (mark) => mark.guarantee,
});
