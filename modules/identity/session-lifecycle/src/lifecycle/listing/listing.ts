import type { Log } from "@mod/kernel";
import type { ClosingList, SubjectSessions } from "../../store.ts";

export interface ListingParts {
	readonly listed: SubjectSessions;
	readonly closings: ClosingList;
	readonly log: Log;
	close(handle: string): Promise<unknown>;
}

export interface Listing {
	/** Takes a closed session off its subject's listing; a failed removal is logged and passed. */
	unlist(subject: string, handle: string): Promise<void>;
	/**
	 * Keeps for closing every session the subject's listing holds awaiting, those a login just pushed
	 * out among them, and closes them; if the closings refuse one, takes the opened session off and
	 * throws, leaving the rest awaiting.
	 */
	closePushedOut(subject: string, opening: string, pushedOut: readonly string[]): Promise<void>;
}

export function listingOver(parts: ListingParts): Listing {
	const { listed, closings, log } = parts;
	/** A closed session left listed costs only a later close, so a failed removal is logged and passed. */
	const unlist = async (subject: string, handle: string) => {
		try {
			await listed.remove(subject, handle);
		} catch (error) {
			log.warn("session-lifecycle.listing_failed", {
				step: "remove",
				kind: error instanceof Error ? error.name : typeof error,
			});
		}
	};
	/**
	 * A pushed-out session awaits in the listing, with its end, until it is kept as a closing and
	 * settled, so neither a refusal nor a crash here loses it: the next push-out and a revocation find it.
	 */
	const closePushedOut = async (subject: string, opening: string, pushedOut: readonly string[]) => {
		log.warn("session-lifecycle.listing_pushed_out", { count: pushedOut.length });
		const kept: string[] = [];
		try {
			for (const handle of await listed.awaiting(subject)) {
				await closings.add(handle);
				await listed.settled(subject, handle);
				kept.push(handle);
			}
		} catch (error) {
			await listed.remove(subject, opening).catch(() => undefined);
			throw error;
		}
		for (const handle of kept) {
			try {
				await parts.close(handle);
			} catch {}
		}
	};
	return { unlist, closePushedOut };
}

/** The handles listed under a subject, those awaiting their closing included: what a revocation closes. */
export const membersOf = (listed: SubjectSessions) => async (subject: string) => [
	...(await listed.members(subject)),
	...(await listed.awaiting(subject)).map((member) => ({ member })),
];
