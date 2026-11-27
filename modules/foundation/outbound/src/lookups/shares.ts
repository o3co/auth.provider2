/** How many names may resolve at once, and the outside party's share of them. */

const defaultThreadpool = 4;

/**
 * Half the threadpool, rounded up, at least one: four threads where `UV_THREADPOOL_SIZE` is unset or
 * unreadable. A lookup by the system's `lookup` runs on the threadpool and no deadline stops it, so names
 * that answer slowly hold at most half of it, leaving the rest to hashing and the file system.
 */
export function threadpoolHalf(threadpool: string | undefined): number {
	const size = /^[1-9]\d*$/.test(threadpool ?? "") ? Number(threadpool) : defaultThreadpool;
	return Math.max(1, Math.floor((size + 1) / 2));
}

/**
 * The lookups at once, and each pool's share: the outside party's half, rounded down, the
 * deployment's own the rest. On the threadpool, the total is first held to half of it.
 */
export function lookupShares(options: {
	readonly maxLookups: number;
	/** Set where lookups run in this process: its threadpool's size, as the environment gives it. */
	readonly onThreadpool?: { readonly threadpool: string | undefined };
}): { readonly total: number; readonly own: number; readonly outside: number } {
	const total =
		options.onThreadpool === undefined
			? options.maxLookups
			: Math.min(options.maxLookups, threadpoolHalf(options.onThreadpool.threadpool));
	const outside = Math.floor(total / 2);
	return { total, own: total - outside, outside };
}
