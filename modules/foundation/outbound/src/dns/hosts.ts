/** The hosts file, read as the system reads it before DNS (`files dns`): each name's addresses. */
import { open } from "node:fs/promises";
import { isIP } from "node:net";
import { hostEntryOf } from "@mod/host-entries";

/** Where the system's hosts file is. */
export const hostsFile = "/etc/hosts";

/** Each name's addresses in the hosts file, IPv4 and IPv6 apart, each in the file's order. */
export type HostsTable = ReadonlyMap<
	string,
	{ readonly v4: readonly string[]; readonly v6: readonly string[] }
>;

/** A name as the hosts file and a lookup compare it: without case, without its trailing dot. */
export const hostsKey = (name: string) => name.replace(/\.$/, "").toLowerCase();

/** The hosts file's table: per line, before `#`, an address and its names; a line with no address skipped. */
export function hostsOf(text: string): HostsTable {
	const table = new Map<string, { v4: Set<string>; v6: Set<string> }>();
	for (const line of text.split(/\r?\n/)) {
		const [address, ...names] = (line.split("#")[0] ?? "").trim().split(/\s+/);
		const version = address === undefined ? 0 : isIP(address);
		if (version === 0 || address === undefined) continue;
		for (const name of names) {
			const key = hostsKey(name);
			const entry = table.get(key) ?? { v4: new Set<string>(), v6: new Set<string>() };
			(version === 4 ? entry.v4 : entry.v6).add(address);
			table.set(key, entry);
		}
	}
	return new Map([...table].map(([name, { v4, v6 }]) => [name, { v4: [...v4], v6: [...v6] }]));
}

/** The longest hosts file read: a larger one is no hosts file a deployment writes. */
export const hostsMaxBytes = 1024 * 1024;

/**
 * The hosts file's text, never more than `hostsMaxBytes` read: none there is empty; one that cannot be
 * read, or longer, is refused with why.
 */
export async function readHostsFile(
	path = hostsFile,
): Promise<{ text: string } | { refused: string }> {
	const opened = await open(path, "r").catch((error: { code?: unknown }) => error);
	if (!("read" in opened)) {
		const missing = (opened as { code?: unknown }).code === "ENOENT";
		return missing ? { text: "" } : { refused: `the hosts file ${path} could not be read` };
	}
	try {
		const buffer = Buffer.alloc(hostsMaxBytes + 1);
		let length = 0;
		while (length < buffer.length) {
			const { bytesRead } = await opened.read(buffer, length, buffer.length - length);
			if (bytesRead === 0) break;
			length += bytesRead;
		}
		if (length > hostsMaxBytes) return { refused: `the hosts file ${path} is over 1 MiB` };
		return { text: buffer.subarray(0, length).toString("utf8") };
	} catch {
		return { refused: `the hosts file ${path} could not be read` };
	} finally {
		await opened.close();
	}
}

/** How many host entries name one label the hosts file lacks: names only the hosts file could answer. */
export const unlistedShortNames = (
	lists: readonly { readonly entries: readonly string[]; readonly port: boolean }[],
	hosts: HostsTable,
) =>
	lists.flatMap(({ entries, port }) =>
		entries.filter((entry) => {
			const read = hostEntryOf(entry, { port });
			return read?.kind === "name" && !read.name.includes(".") && !hosts.has(hostsKey(read.name));
		}),
	).length;
