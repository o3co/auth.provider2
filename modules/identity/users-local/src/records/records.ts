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

/** What the ledger needs of its records: none dropped or lost, and a read never taken back. */
const guarantees: readonly Guarantee[] = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
];

/** Each identifier's record, keyed by the identifier: its subject, and the password's hash where one is held. */
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

export type IdentifierRecord = { readonly subject: string; readonly "password-hash"?: string };
export type SubjectRecord = { readonly identifier: string };

type Places = "identifiers" | "subjects";
/** The builders the module makes over its two spaces, at the phase the process reads once. */
export interface Builders {
	readonly identifiers: Awaited<ReturnType<typeof phasedRecordsIn<IdentifierRecord>>>;
	readonly subjects: Awaited<ReturnType<typeof phasedRecordsIn<SubjectRecord>>>;
	readonly joint: Awaited<ReturnType<typeof phasedJointRecordsIn<Places>>>;
}

/** The builders over the two spaces, at the one phase this process reads: the module's own, taken by no other. */
export const placed = contract<Builders>("users-local.placed");

/** The ledger's records: a user placed by identifier and subject as one, and each read back. */
export interface LocalRecords {
	/** Places the user, unless the identifier is held (`exists`); unavailable where the subject is held or erased. */
	place(identifier: string, subject: string, passwordHash?: string): Promise<"placed" | "exists">;
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
const identifierShaped = (read: Record<string, unknown>) =>
	isText(read.subject) && (read["password-hash"] === undefined || isText(read["password-hash"]));

export function localRecords(builders: Builders): LocalRecords {
	return {
		place: async (identifier, subject, passwordHash) => {
			const held: IdentifierRecord =
				passwordHash === undefined ? { subject } : { subject, "password-hash": passwordHash };
			const answer: JointAnswer = await builders.joint.changeSubjectRecords({
				targets: [
					{ place: "identifiers", key: identifier },
					{ place: "subjects", key: subject },
				],
				decide: () => ({
					targets: [
						{ kind: "create", value: held, lifetimeMs: "endless", subject },
						{ kind: "create", value: { identifier }, lifetimeMs: "endless", subject },
					],
				}),
			});
			if (answer.kind === "written") return "placed";
			// Only the identifier's record held answers exists: a subject held or erased is no answer to give.
			if (answer.why === "exists" && answer.at.nth === 0) return "exists";
			throw new Unavailable("users-local");
		},
		byIdentifier: async (identifier) =>
			shaped<IdentifierRecord>(await builders.identifiers.read(identifier), identifierShaped),
		bySubject: async (subject) =>
			shaped<SubjectRecord>(await builders.subjects.read(subject), (read) =>
				isText(read.identifier),
			),
	};
}

/** Whose a record written before indexing is: an identifier's names its subject, a subject's is keyed by it. */
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

/** The eraser `users-local`, as its spaces' `erasedBy` names it: a subject's two records erased, and both spaces migrated once. */
export function localEraser(builders: Pick<Builders, "identifiers" | "subjects">): Eraser {
	const spaces: readonly [Erasing, SubjectReading][] = [
		[builders.identifiers, identifierReading],
		[builders.subjects, subjectReading],
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
		// Both spaces are indexed by their subject: no walk reaches more.
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
