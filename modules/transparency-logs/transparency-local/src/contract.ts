import { contract } from "@mod/kernel";
import type { Json } from "@mod/transparency";

/**
 * The store interface of the log kept in the Core (`transparency-local`): its records by key, read,
 * then written as one held to every version read. A wiring provides it, by `logStoreOver`.
 */

/** What a read of the log's records saw, which its one write is held to. */
export interface LogRead {
	/** Each record's value, in the order named; none where it holds none. */
	readonly values: readonly (Json | undefined)[];
	/** The store clock's time at the read. */
	readonly now: number;
	/** Opaque to the caller: what the store holds the write to. */
	readonly basis: unknown;
}

export interface LogStore {
	read(keys: readonly string[]): Promise<LogRead>;
	/**
	 * Writes each record's next value (none keeps it) as one, kept without end, held to every version
	 * the read saw, refused past `deadline` on the store clock. Unavailable means it may have applied.
	 */
	write(
		read: LogRead,
		next: readonly (Json | undefined)[],
		deadline: number,
	): Promise<"written" | "moved" | "late">;
}

export const logStore = contract<LogStore>("transparency-local.store");

/** What the log's place must be, each need a guarantee its wiring declares. */
export const logStoreNeeds = Object.freeze({
	/** A record dropped for room would free its position for another, and lose the flow's state. */
	neverEvicted: "never evicted",
	/** A crash losing a record would lose a stage the Core took in, or answered a receipt for. */
	survivesCrash: "survives a crash",
	survivesFailover: "survives a failover",
	/** An append decides on what another replica placed: the head, an op's stages. */
	readsConfirmed: "reads confirmed",
	/** A record written outside the provider would place a stage, or judge one, the Core never did. */
	authenticated: "written by the provider alone",
});

export { logStoreOver } from "./store.ts";
