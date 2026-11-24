import { sourcedAttributesShape } from "@mod/login-attributes";
import type { AuthContext } from "@mod/session";
import { z } from "zod";
import type { StoredSession } from "../store.ts";

/** When the session opened and when it ends (epoch ms): its own length is the one between. */
type Times = { readonly openedAt: number; readonly endsAt: number };

type Full = AuthContext &
	Times & {
		/** When closing began, and when a sweep may next go on with it (epoch ms). */
		readonly closingSince?: number;
		readonly retryAt?: number;
	};

/** What a session keeps from its login to its end, by state; a closed one keeps its subject and times alone. */
export type SessionRecord = { readonly format: 1 } & (
	| (Full & { readonly state: "open" })
	| (Full & { readonly state: "closing" })
	| (Times & { readonly state: "closed"; readonly subject: string })
);

const timesShape = { format: z.literal(1), openedAt: z.number(), endsAt: z.number() };
const fullShape = z.strictObject({
	...timesShape,
	state: z.enum(["open", "closing"]),
	subject: z.string(),
	amr: z.array(z.string()),
	authenticatedAt: z.number(),
	authenticatedAtUnknown: z.literal(true).optional(),
	attributes: sourcedAttributesShape.optional(),
	closingSince: z.number().optional(),
	retryAt: z.number().optional(),
});
const closedShape = z.strictObject({
	...timesShape,
	state: z.literal("closed"),
	subject: z.string(),
});
const recordShape = z.union([fullShape, closedShape]);

export const toStored = (record: SessionRecord) => record as unknown as StoredSession;
/** Closed: its subject and times; a login's attributes, amr and authentication time dropped. */
export const closedFrom = (was: SessionRecord): SessionRecord => ({
	format: 1,
	state: "closed",
	subject: was.subject,
	openedAt: was.openedAt,
	endsAt: was.endsAt,
});
/** The record a kept value holds, checked on every read; nothing for a format or shape this does not know. */
export const fromStored = (stored: StoredSession | undefined): SessionRecord | undefined => {
	const read = recordShape.safeParse(stored);
	return read.success ? (read.data as SessionRecord) : undefined;
};
/** A session's own length, from its opening to its end, at least a millisecond. */
export const lengthOf = (record: Times) => Math.max(1, record.endsAt - record.openedAt);
