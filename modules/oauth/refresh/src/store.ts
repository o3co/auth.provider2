import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A record as the store keeps it: the store never reads it, and only refresh opens it. */
export type StoredFamilyRecord = { readonly [stored]: true };

/** A record as a change leaves it; it keeps its end. */
export interface ChangedFamilyRecord {
	readonly value: StoredFamilyRecord;
}

/**
 * Where refresh's records are kept, by name: families, the key each is bound to, and what each code
 * founded; offering `erase` and `migrate` together or neither, a part refusing the boot. Every call
 * throws Unavailable when the place cannot tell.
 */
export interface FamilyRecords {
	/**
	 * Keeps a record for its lifetime and its subject, unless the name holds one already (`exists`)
	 * or, where the Store fences creation past a subject's erasure, the subject is erased (`erased`).
	 */
	create(
		name: string,
		record: StoredFamilyRecord,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(name: string): Promise<StoredFamilyRecord | undefined>;
	/** Changes the record from what it holds, answering it before and after; `change` reruns on a race, so it is pure. Nothing when gone. */
	change(
		name: string,
		change: (record: StoredFamilyRecord) => ChangedFamilyRecord | undefined,
	): Promise<
		{ readonly before: StoredFamilyRecord; readonly after: StoredFamilyRecord } | undefined
	>;
	/** Erases a subject's records here, where the Store can. */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key; offered with `erase`. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

export const familyRecords = contract<FamilyRecords>("refresh.records");

/**
 * A lost family would end a delegation early; one rolled back would bring an ended family back, and
 * one written outside the provider would found a family no approval made: none of these may happen.
 */
export const familyRecordsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
	authenticated: true,
} as const;
