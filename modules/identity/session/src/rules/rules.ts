import {
	authenticatedAtOf,
	checkAuthenticatedAt,
	checkEndsAt,
	checkProvenSince,
} from "./authenticated.ts";
import { closeListed } from "./listed.ts";

/** The rules every implementation of sessions keeps, the stand-in too, each in its one order. */
export const sessionRules = Object.freeze({
	closeListed,
	checkAuthenticatedAt,
	checkProvenSince,
	checkEndsAt,
	authenticatedAtOf,
});
