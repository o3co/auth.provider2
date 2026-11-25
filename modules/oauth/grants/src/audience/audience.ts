import { contract, extensionPoint } from "@mod/kernel";

/** For an issuance's audience: the request's parameters, the audience when none is asked, and whether the issuance may have another (its owner decides). */
export interface TargetRequest {
	readonly param: (name: string) => string | undefined;
	readonly audience: readonly string[];
	readonly within: (audience: string) => boolean;
}
export type TargetVerdict =
	| { readonly kind: "audience"; readonly audience: readonly string[] }
	| { readonly kind: "error"; readonly error: "invalid_target"; readonly description: string };
/** A rule for the audience a request asks for, as resource indicators (RFC 8707) contribute. */
export interface TargetRule {
	target(request: TargetRequest): TargetVerdict;
	/** For a grant that takes no audience, or another endpoint that asks: a refusal when the request asks one anyway. */
	untargeted?(
		request: Pick<TargetRequest, "param">,
	): Extract<TargetVerdict, { readonly kind: "error" }> | undefined;
	/** For a parameter sent more than once: a refusal when it is one the rule reads. */
	repeated?(name: string): Extract<TargetVerdict, { readonly kind: "error" }> | undefined;
}
/** At most one; two refuse boot. */
export const targetRules = extensionPoint<TargetRule>("grants.target-rules", {
	multiplicity: "many",
});
/** The composed rule, provided by the token endpoint; with none, the default audience, the request unread. */
export const targets = contract<TargetRule>("grants.targets");
