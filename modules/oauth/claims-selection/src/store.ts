import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A selection's record as the store keeps it: the store never reads it, and only claims-selection opens it. */
export type StoredSelection = { readonly [stored]: true };

/**
 * Where selections are kept, by name, offering `erase` and `migrate` together or neither; a part
 * refuses the boot. Every call throws Unavailable when the place cannot tell.
 */
export interface SelectionRecords {
	/**
	 * Keeps a record for its lifetime and its subject, unless the name holds one already (`exists`)
	 * or, where the Store fences creation past a subject's erasure, the subject is erased (`erased`).
	 */
	create(
		name: string,
		record: StoredSelection,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(name: string): Promise<StoredSelection | undefined>;
	/** Erases a subject's records here, where the Store can. */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key; offered with `erase`. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

export const selectionRecords = contract<SelectionRecords>("claims-selection.records");

/**
 * A lost record would let a claim its constraint holds back go out unconstrained, so none is lost
 * to eviction, a crash or a failover; one written outside the provider could release names no
 * person agreed to.
 */
export const selectionRecordsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/**
	 * The pin reads the code's selection: a stale read answering none would pin no selection, and the
	 * constraints it held would go unread; a pin read stale fails the redemption.
	 */
	confirmedReads: true,
	authenticated: true,
} as const;
