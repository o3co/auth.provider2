import { contract } from "@mod/kernel";

/** The refresh grant's type (RFC 6749 §6). */
export const refreshGrantType = "refresh_token";

/** How long a login's delegation lasts, from its statement's issue (O27): a family's, and its session's. */
export interface Delegation {
	readonly lifetimeMs: number;
}

export const delegation = contract<Delegation>("refresh.delegation");

export { familiesPart } from "./state/state.ts";
export * from "./store.ts";
