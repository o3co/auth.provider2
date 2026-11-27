/** Lookups in this process by DNS (node's c-ares resolver), the hosts file first: each one stoppable. */
import type { Job } from "../resolver-process/contract.ts";
import { poolLimits } from "../resolver-process/contract.ts";
import { type HostsTable, hostsKey } from "./hosts.ts";

/** What a lookup asks of a resolver: its A and AAAA records, and to stop. */
export interface DnsResolver {
	resolve4(name: string): Promise<string[]>;
	resolve6(name: string): Promise<string[]>;
	cancel(): void;
}

/**
 * Each query's wait and tries. With a dead first nameserver, a lookup reaches the next after one to
 * two waits (measured: 1 to 2 s), every lookup alike, as each has its own resolver; the caller's
 * deadline still ends it first where it is shorter.
 */
export const resolverTimings = Object.freeze({ timeout: 1_000, tries: 2 });

/** Records absent: no such name, or none of that family. */
const absent = new Set(["ENOTFOUND", "ENODATA"]);

/** A name made absolute (one trailing dot), so no search list or `ndots` applies. */
export const absolute = (name: string) => (name.endsWith(".") ? name : `${name}.`);

/** `name`'s addresses: the hosts file's, else DNS's queried absolute, A then AAAA (A alone for IPv4). */
async function addressesOf(
	name: string,
	family: 4 | undefined,
	hosts: HostsTable,
	resolver: DnsResolver,
	stopped: () => boolean,
): Promise<readonly string[]> {
	const listed = hosts.get(hostsKey(name));
	const fromHosts =
		listed === undefined ? [] : family === 4 ? listed.v4 : [...listed.v4, ...listed.v6];
	if (fromHosts.length > poolLimits.maxAddresses) throw new Error("too many addresses");
	if (fromHosts.length > 0) return fromHosts;
	// A single label the hosts file lacks is never sent: no search list completes it.
	if (!hostsKey(name).includes("."))
		throw Object.assign(new Error("single label"), { code: "ENOTFOUND" });
	// Left by every waiter before it was sent: a cancel reaches only queries sent.
	if (stopped()) throw Object.assign(new Error("cancelled"), { code: "ECANCELLED" });
	const query = absolute(name);
	const asked =
		family === 4
			? [resolver.resolve4(query)]
			: [resolver.resolve4(query), resolver.resolve6(query)];
	const answers = await Promise.allSettled(asked);
	const found = answers.flatMap((a) => (a.status === "fulfilled" ? a.value : []));
	// A family that failed, not one found absent, fails the lookup: every family's addresses are checked.
	const failed = answers.find(
		(a): a is PromiseRejectedResult =>
			a.status === "rejected" && !absent.has((a.reason as { code?: unknown })?.code as string),
	);
	if (failed) throw failed.reason;
	if (found.length === 0) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
	if (found.length > poolLimits.maxAddresses) throw new Error("too many addresses");
	return found;
}

/** At most `size` lookups at once, each its own resolver, cancelled once its last waiter leaves. */
export function caresPool(
	size: number,
	p: { readonly hosts: HostsTable; readonly resolver: () => DnsResolver },
): { run(name: string, family?: 4): Job | undefined } {
	let running = 0;
	return {
		run: (name, family) => {
			if (running >= size) return undefined;
			// A resolver that cannot be made takes no place.
			const resolver = p.resolver();
			running += 1;
			let waiting = 1;
			let ended = false;
			const end = () => {
				if (ended) return;
				ended = true;
				running -= 1;
			};
			// Started inside the chain, so a resolver that throws at once is caught as well.
			const answer = Promise.resolve()
				.then(() => addressesOf(name, family, p.hosts, resolver, () => ended))
				.finally(end);
			answer.catch(() => {});
			return {
				answer,
				want: () => {
					if (ended) return false;
					waiting += 1;
					return true;
				},
				unwant: () => {
					waiting -= 1;
					// No one waits: the lookup is stopped, its place given back now, not when DNS answers.
					if (waiting <= 0 && !ended) {
						end();
						resolver.cancel();
					}
				},
			};
		},
	};
}
