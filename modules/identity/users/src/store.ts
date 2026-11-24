import type {
	Elsewhere,
	MigrationReport,
	SpaceReport,
	SubjectReading,
	Walk,
} from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

declare const storedContacts: unique symbol;
/** A subject's verified contacts, as the store keeps them: only users opens them. */
export type StoredContacts = { readonly [storedContacts]: true };

/** A record as a change leaves it. */
export interface Changed<T> {
	readonly value: T;
}

/** Records by key, kept without end, each changed only from what it holds. Every call throws Unavailable when the store cannot tell. */
export interface RecordStore<T> {
	/** Keeps a new record, unless the key holds one. */
	save(key: string, record: T, lifetimeMs: "endless"): Promise<"created" | "exists">;
	read(key: string): Promise<T | undefined>;
	/** Changes the record from what it holds, or leaves it on none; `change` runs again on a race, so it is pure. Nothing when gone. */
	update(
		key: string,
		change: (record: T) => Changed<T> | undefined,
	): Promise<{ readonly before: T; readonly after: T } | undefined>;
}

/**
 * Records of subjects by key, as `RecordStore`, each saved with the subject it is kept for, last: a
 * store that keeps the subject apart (to find and erase a subject's records) takes it; one that does
 * not may ignore it.
 */
export interface SubjectRecordStore<T> extends Omit<RecordStore<T>, "save"> {
	/**
	 * Keeps a new record for its subject, unless the key holds one (`exists`) or, where the store
	 * fences saves past a subject's erasure, the subject is erased there (`erased`), which users
	 * takes as unavailable.
	 */
	save(
		key: string,
		record: T,
		lifetimeMs: "endless",
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	/**
	 * Erases a subject's records here, where the store can: optional in 0.20, required in 0.22; a
	 * store without it holds records users' eraser cannot erase. Offered with `migrate`, or neither.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/**
	 * Once, under the maintenance key: puts the records written before indexing into the index, each
	 * read by `subjectOf`, users', with `elsewhere` keeping what an orphan holds that users still
	 * needs, so the store never opens a record.
	 */
	migrate?(
		walk: Walk,
		subjectOf: SubjectReading,
		signal: AbortSignal,
		elsewhere?: Elsewhere,
	): Promise<MigrationReport>;
}

export type ContactStore = SubjectRecordStore<StoredContacts>;

export const contactStore = contract<ContactStore>("users.contact-store");

/** Losing a verified contact would make its owner verify it again. */
export const contactStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
