import { stopAll } from "../../lifecycle/lifecycle.ts";

/** A part's stop, as a run's body holds it. */
export type Held = (stop: () => Promise<unknown>) => void;

/** How long a body ended by its signal may take to end, past which it is told and left. */
export const bodyEndsWithinMs = 20 * 60_000;

/** Thrown to a body that starts a part once ended: the part is stopped, the body goes no further. */
class Ending extends Error {}

/**
 * Runs `body`, each part it starts held by its stop, until it ends or `signal` does, whatever it still
 * waits on. Ended by the signal, every part held is stopped at once, and a part the body starts after
 * is stopped and the body thrown out there; the body is then awaited (within `bodyEndsWithinMs`), and
 * the later stops. Answers how the run ended; what the body answered or failed of its own after the
 * signal (a part it stopped itself among it, for the caller to judge); and every failure to stop.
 */
export async function stoppedWhenEnded<T>(
	signal: AbortSignal,
	body: (held: Held) => Promise<T>,
	endsWithinMs: number = bodyEndsWithinMs,
): Promise<{
	readonly ran: { readonly value: T } | { readonly failed: unknown };
	readonly after?: { readonly value: T } | { readonly failed: unknown };
	readonly problems: unknown[];
}> {
	const stops: (() => Promise<unknown>)[] = [];
	/** Each stop of a part started once ended, its failure caught as it starts. */
	const late: Promise<{ readonly failed: unknown } | undefined>[] = [];
	let ending = false;
	const held: Held = (stop) => {
		if (!ending) {
			stops.push(stop);
			return;
		}
		late.push(
			stop().then(
				() => undefined,
				(failed: unknown) => ({ failed }),
			),
		);
		throw new Ending("the run was ended before this part started");
	};
	const ended = () => new Error(`ended: ${String(signal.reason)}`);
	if (signal.aborted) return { ran: { failed: ended() }, problems: [] };
	const stopped = new Promise<"ended">((done) =>
		signal.addEventListener("abort", () => done("ended"), { once: true }),
	);
	const running = body(held).then(
		(value) => ({ value }),
		(failed: unknown) => ({ failed }),
	);
	const first = await Promise.race([running, stopped]);
	ending = true;
	const problems = await stopAll(stops);
	if (first !== "ended") {
		for (const r of await Promise.all(late)) if (r !== undefined) problems.push(r.failed);
		return { ran: first, problems };
	}
	const after = await Promise.race([
		running,
		new Promise<"late">((done) => setTimeout(() => done("late"), endsWithinMs).unref()),
	]);
	if (after === "late")
		problems.push(new Error(`the run's body did not end within ${endsWithinMs} ms of its signal`));
	const told = after !== "late" && !("failed" in after && after.failed instanceof Ending);
	for (const r of await Promise.all(late)) if (r !== undefined) problems.push(r.failed);
	return {
		ran: { failed: ended() },
		...(told ? { after } : {}),
		problems,
	};
}
