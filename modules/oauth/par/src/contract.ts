import { contract } from "@mod/kernel";

declare const storedPush: unique symbol;
/** A pushed request as kept: opaque to the store. */
export type StoredPush = { readonly [storedPush]: true };

/** Where pushed requests are kept, by their `request_uri`. Throws Unavailable when it cannot tell. */
export interface PushedRequests {
	/** Keeps the record for its lifetime, unless one is kept already. */
	create(key: string, record: StoredPush, lifetimeMs: number): Promise<"created" | "exists">;
	read(key: string): Promise<StoredPush | undefined>;
}

export const pushedRequests = contract<PushedRequests>("par.pushed-requests");

/**
 * What the pushed requests' place must be, each a guarantee its wiring declares. A record lost only
 * fails the login that names it; its JAR is verified again where the login starts.
 */
export const pushedRequestsNeeds = {
	/** A request just pushed must be found where the login starts, on any replica. */
	confirmedReads: true,
	survivesFailover: true,
	/** One pushed for a minute and dropped for room would fail logins at random. */
	neverEvicted: true,
	/** A record written outside the provider could put another JAR of the same client under a request_uri. */
	authenticated: true,
} as const;
