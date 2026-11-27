# dns

Internal module of `outbound`: name lookups in this process by DNS (node's c-ares resolver), the hosts file first, each stopped at its deadline.

## Responsibilities
- Answers a name from the hosts file where it lists it, else by DNS, each lookup with a resolver of its own, so it is cancelled once no one waits on it.

## Not here
- Sharing a lookup among those waiting on it, each one's deadline, and the pools' shares: `lookups`.
- Lookups as the system resolves them (search list, nsswitch), in helper processes: `resolver-process`.

## Offers
- `caresPool(size, { hosts, resolver })` → a pool whose `run(name, family?)` is a `Job`, or none where no place is free.
- `readHostsFile` (at most 1 MiB read: the text, empty where none is there, or why refused).
- `hostsOf` (the text → each name's IPv4 and IPv6 addresses, in the file's order, each once), `hostsFile` (`/etc/hosts`), `hostsKey`, `unlistedShortNames` (how many host entries name one label the hosts file lacks); `resolverTimings` (each query's 1 s wait and 2 tries: past a dead first nameserver, each lookup reaches the next in 1 to 2 s, measured, unless its caller's deadline ends it first); `absolute` (a name with its one trailing dot); `DnsResolver`, what a lookup asks of node's resolver.

## Invariants
- A name the hosts file lists for the family asked is answered from it, compared without case or trailing dot: its lines merged, IPv4 before IPv6, each in the file's order and once (a scoped address as written); IPv4 alone for family 4.
- A family the hosts file lists none of for a name is asked of DNS, as the system does. The module reads the file once, at the start, refusing boot where it cannot be read or is over 1 MiB; none there is none listed, so `localhost` resolves only where it is (never on Windows, whose file is elsewhere).
- Else a name of one label is never sent (no search list completes it): it fails as not found.
- Else it is queried absolute (node's resolver applies no search list itself; the trailing dot holds it too), so no search list or `ndots` applies: A then AAAA for every family, A alone for IPv4. A family absent leaves the other's; a family whose query failed (a timeout, a server failure) fails the lookup, so no family's addresses go unchecked; none found fails it as not found; more than 64 addresses, from DNS or the hosts file, fail it.
- A lookup left by its last waiter is cancelled at once (its queries, through its own resolver), its place given back and joined no more; one left before it sent a query sends none. Another waiter's deadline cancels nothing a waiter still needs.
- Not consulted: the system's resolver (nsswitch, nscd), mDNS, LDAP. Queries go to the nameservers `resolv.conf` lists, which may be a caching stub (systemd-resolved's, NodeLocal DNSCache).

## Depends on
- node's `dns/promises` (`Resolver`, by the module), `fs/promises` (`open`) and `net` (`isIP`); `host-entries` (`hostEntryOf`); `resolver-process` (`Job`, `poolLimits`).
