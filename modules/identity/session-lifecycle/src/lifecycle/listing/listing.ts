import type { Log } from "@mod/kernel";
import type { ClosingList, SubjectSessions } from "../../store.ts";

export interface ListingParts {
	readonly listed: SubjectSessions;
	readonly closings: ClosingList;
	readonly log: Log;
	close(handle: string): Promise<unknown>;
}

export interface Listing {
	/** Takes a closed session off its subject's listing and off those awaiting; a failed write is logged and passed. */
	unlist(subject: string, handle: string): Promise<void>;
	/**
	 * Keeps for closing every session the subject's listing holds awaiting, those a login just pushed
	 * out among them, and closes them; if the closings refuse one, takes the opened session off and
	 * throws, leaving the rest awaiting, for this host's sweep to take up.
	 */
	closePushedOut(subject: string, opening: string, pushedOut: readonly string[]): Promise<void>;
	/** Whether the handle awaits its closing in the subject's listing. */
	awaits(subject: string, handle: string): Promise<boolean>;
	/** Takes up, once a sweep, what a refused push-out left awaiting on this host; a subject still refused stays. */
	retryAwaiting(stopping: AbortSignal): Promise<void>;
}

export function listingOver(parts: ListingParts): Listing {
	const { listed, closings, log } = parts;
	/** The subjects a refused push-out left sessions awaiting under, as this host saw it. */
	const refused = new Set<string>();
	const passed = (step: string) => (error: unknown) => {
		log.warn("session-lifecycle.listing_failed", {
			step,
			kind: error instanceof Error ? error.name : typeof error,
		});
	};
	/** A closed session left listed or awaiting costs only a later close, so a failed write is logged and passed. */
	const unlist = async (subject: string, handle: string) => {
		await listed.remove(subject, handle).catch(passed("remove"));
		await listed.settled(subject, handle).catch(passed("settle"));
	};
	/**
	 * A pushed-out session awaits in the listing, with its end, until a close of it finishes and
	 * settles it, so neither a refusal nor a crash here lets anyone in: no record is read to keep it.
	 */
	const keepAwaiting = async (subject: string) => {
		const kept = await listed.awaiting(subject);
		for (const handle of kept) await closings.add(handle);
		for (const handle of kept) {
			try {
				await parts.close(handle);
			} catch {}
		}
	};
	const closePushedOut = async (subject: string, opening: string, pushedOut: readonly string[]) => {
		log.warn("session-lifecycle.listing_pushed_out", { count: pushedOut.length });
		try {
			await keepAwaiting(subject);
		} catch (error) {
			refused.add(subject);
			await listed.remove(subject, opening).catch(() => undefined);
			throw error;
		}
	};
	const retryAwaiting = async (stopping: AbortSignal) => {
		for (const subject of [...refused]) {
			if (stopping.aborted) return;
			try {
				await keepAwaiting(subject);
				refused.delete(subject);
			} catch {}
		}
	};
	const awaits = async (subject: string, handle: string) =>
		(await listed.awaiting(subject)).includes(handle);
	return { unlist, closePushedOut, awaits, retryAwaiting };
}

/** The handles listed under a subject, those awaiting their closing included: what a revocation closes. */
export const membersOf = (listed: SubjectSessions) => async (subject: string) => [
	...(await listed.members(subject)),
	...(await listed.awaiting(subject)).map((member) => ({ member })),
];
