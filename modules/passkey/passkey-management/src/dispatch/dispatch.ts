/** Resolves once the signal aborts. */
const abortOf = (signal: AbortSignal) =>
	new Promise<void>((resolve) => {
		if (signal.aborted) resolve();
		else signal.addEventListener("abort", () => resolve(), { once: true });
	});

/** What the dispatch tells of a job: one dropped, never run, and one that threw. */
export interface Told {
	dropped(): void;
	failed(error: unknown): void;
}

/** Jobs run apart from the answers that put them, up to `max` under way. */
export interface Dispatch {
	/** Puts a job, never waiting: dropped where `max` are under way, or before start or past stop. */
	put(job: () => Promise<void>): void;
	start(): void;
	/** Takes no more, and waits for those under way until the signal aborts. */
	stop(signal: AbortSignal): Promise<void>;
}

export function dispatchOver(p: { readonly max: number; readonly told: Told }): Dispatch {
	let open = false;
	const underWay = new Set<Promise<void>>();
	return {
		put: (job) => {
			if (!open || underWay.size >= p.max) {
				p.told.dropped();
				return;
			}
			// Deferred, so the put returns first, and a job that throws at once fails like one that rejects.
			const run: Promise<void> = Promise.resolve()
				.then(job)
				.catch((error: unknown) => p.told.failed(error))
				.finally(() => underWay.delete(run));
			underWay.add(run);
		},
		start: () => {
			open = true;
		},
		stop: async (signal) => {
			open = false;
			await Promise.race([Promise.allSettled([...underWay]), abortOf(signal)]);
		},
	};
}
