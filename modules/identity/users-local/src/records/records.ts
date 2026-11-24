import type {
	Eraser,
	MigrationReport,
	SpaceReport,
	SubjectOf,
	SubjectReading,
	Walk,
} from "@mod/erasure-extensions";
import { contract, Unavailable } from "@mod/kernel";
import type { Guarantee, Space } from "@mod/store";
import type { JointAnswer, phasedJointRecordsIn, phasedRecordsIn } from "@mod/subject-records";

/** What the ledger needs of its records: none dropped or lost, a read never taken back, and no outside write taken as its own. */
const guarantees: readonly Guarantee[] = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
	// One write made outside the provider could tie another's subject to an identifier.
	"authenticated",
];

/** Each identifier's record, keyed by the identifier: its subject, and its password's hash where one was brought. */
export const identifierSpace: Space = {
	name: "users-local.identifiers",
	guarantees,
	subjectData: "online-indexed",
	erasedBy: "users-local",
};
/** Each subject's record, keyed by the subject: the identifier it was made for. */
export const subjectSpace: Space = {
	name: "users-local.subjects",
	guarantees,
	subjectData: "online-indexed",
	erasedBy: "users-local",
};

/** The passkey witness's mark of each subject, keyed by the subject: the token that set it. */
export const markSpace: Space = {
	name: "users-local.marks",
	guarantees,
	subjectData: "online-keyed",
	erasedBy: "users-local",
};

export type IdentifierRecord = { readonly subject: string; readonly passwordHash?: string };
export type SubjectRecord = { readonly identifier: string };
export type MarkRecord = { readonly token: string };

type Places = "identifiers" | "subjects";
/** The builders the module makes over its two spaces, at the phase the process reads once. */
export interface Builders {
	readonly identifiers: Awaited<ReturnType<typeof phasedRecordsIn<IdentifierRecord>>>;
	readonly subjects: Awaited<ReturnType<typeof phasedRecordsIn<SubjectRecord>>>;
	readonly joint: Awaited<ReturnType<typeof phasedJointRecordsIn<Places>>>;
	readonly marks: Awaited<ReturnType<typeof phasedRecordsIn<MarkRecord>>>;
}

/** The builders over the three spaces, at the one phase this process reads: the module's own, taken by no other. */
export const placed = contract<Builders>("users-local.placed");

/** The ledger's records: a user placed by identifier and subject as one, and each read back. */
export interface LocalRecords {
	/**
	 * Places the user, with its password's hash where given, unless the identifier is held (`exists`),
	 * else the subject (`taken`), else the subject is erased (`erased`).
	 */
	place(
		identifier: string,
		subject: string,
		passwordHash?: string,
	): Promise<"placed" | "exists" | "taken" | "erased">;
	byIdentifier(identifier: string): Promise<IdentifierRecord | undefined>;
	bySubject(subject: string): Promise<SubjectRecord | undefined>;
}

const isText = (value: unknown): value is string => typeof value === "string" && value !== "";

/** A record read as the shape it was written in; another shape is unavailable, never none. */
function shaped<T>(
	value: unknown,
	holds: (read: Record<string, unknown>) => boolean,
): T | undefined {
	if (value === undefined) return undefined;
	const read = value as Record<string, unknown> | null;
	if (read === null || typeof read !== "object" || Array.isArray(read) || !holds(read)) {
		throw new Unavailable("users-local");
	}
	return value as T;
}

export function localRecords(builders: Builders): LocalRecords {
	return {
		place: async (identifier, subject, passwordHash) => {
			const answer: JointAnswer = await builders.joint.changeSubjectRecords({
				targets: [
					{ place: "identifiers", key: identifier },
					{ place: "subjects", key: subject },
				],
				decide: () => ({
					targets: [
						{
							kind: "create",
							value: passwordHash === undefined ? { subject } : { subject, passwordHash },
							lifetimeMs: "endless",
							subject,
						},
						{ kind: "create", value: { identifier }, lifetimeMs: "endless", subject },
					],
				}),
			});
			if (answer.kind === "written") return "placed";
			// The identifier's record is the first target, so a held identifier is told before its subject.
			if (answer.why === "exists") return answer.at.nth === 0 ? "exists" : "taken";
			if (answer.why === "erased") return "erased";
			throw new Unavailable("users-local");
		},
		byIdentifier: async (identifier) =>
			shaped<IdentifierRecord>(
				await builders.identifiers.read(identifier),
				(read) =>
					isText(read.subject) && (read.passwordHash === undefined || isText(read.passwordHash)),
			),
		bySubject: async (subject) =>
			shaped<SubjectRecord>(await builders.subjects.read(subject), (read) =>
				isText(read.identifier),
			),
	};
}

/** The witness's marks: one per subject, set unless one is, and removed only where it is the token's. */
export interface LocalMarks {
	/** Sets the subject's mark to `token`, unless one is set (`exists`) or the subject is erased (`erased`). */
	set(subject: string, token: string): Promise<"created" | "exists" | "erased">;
	read(subject: string): Promise<MarkRecord | undefined>;
	/** Removes the mark only where it is `token`'s, checked in the write that removes it. */
	remove(subject: string, token: string): Promise<void>;
}

export function localMarks(builders: Pick<Builders, "marks">): LocalMarks {
	return {
		set: (subject, token) => builders.marks.create(subject, { token }, "endless", subject),
		read: async (subject) =>
			shaped<MarkRecord>(await builders.marks.read(subject), (read) => isText(read.token)),
		remove: async (subject, token) => {
			await builders.marks.remove(subject, (held) => held.token === token);
		},
	};
}

/** Whose a record written before indexing is: an identifier's names its subject, a subject's and a mark's are keyed by it. */
const identifierReading: SubjectReading = async (_key, value): Promise<SubjectOf> => {
	const subject = (value as { subject?: unknown } | null)?.subject;
	return isText(subject)
		? { kind: "subject", subject }
		: { kind: "unreadable", reason: "an identifier record of another shape" };
};
const subjectReading: SubjectReading = async (key) => ({ kind: "subject", subject: key });

/** A space's builder as the eraser uses it. */
interface Erasing {
	erase(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	migrate(walk: Walk, subjectOf: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

/** The eraser `users-local`, as its spaces' `erasedBy` names it: a subject's records and mark erased, and each space migrated once. */
export function localEraser(
	builders: Pick<Builders, "identifiers" | "subjects" | "marks">,
): Eraser {
	const spaces: readonly [Erasing, SubjectReading][] = [
		[builders.identifiers, identifierReading],
		[builders.subjects, subjectReading],
		[builders.marks, subjectReading],
	];
	const online = async (subject: string, signal: AbortSignal) => {
		const reports = [];
		for (const [space] of spaces) reports.push(await space.erase(subject, signal));
		return { reports, logoutGaps: 0 };
	};
	return {
		name: "users-local",
		erasable: true,
		online,
		// Each space is indexed or keyed by its subject: no walk reaches more.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => {
			const reports = [];
			for (const [space, reading] of spaces)
				reports.push(await space.migrate(walk, reading, signal));
			return reports;
		},
	};
}
