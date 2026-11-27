import dgram from "node:dgram";
import { Resolver } from "node:dns/promises";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { lookupsOver } from "../../lookups/contract.ts";
import { absolute, caresPool, type DnsResolver, resolverTimings } from "../cares.ts";
import { hostsMaxBytes, hostsOf, readHostsFile, unlistedShortNames } from "../hosts.ts";

/** A resolver answering from a table, recording what it was asked and whether it was cancelled. */
function tableResolver(records: Record<string, { a?: string[]; aaaa?: string[]; error?: string }>) {
	const asked: string[] = [];
	let cancelled = 0;
	const pending: (() => void)[] = [];
	const answer = (name: string, kind: "a" | "aaaa", hold: boolean) =>
		new Promise<string[]>((resolve, reject) => {
			asked.push(`${kind} ${name}`);
			const go = () => {
				const r = records[name];
				if (r?.error) return reject(Object.assign(new Error(r.error), { code: r.error }));
				const found = r?.[kind];
				return found
					? resolve(found)
					: reject(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
			};
			if (hold)
				pending.push(() => reject(Object.assign(new Error("ECANCELLED"), { code: "ECANCELLED" })));
			else go();
		});
	const make = (hold = false): DnsResolver => ({
		resolve4: (name) => answer(name, "a", hold),
		resolve6: (name) => answer(name, "aaaa", hold),
		cancel: () => {
			cancelled += 1;
			for (const reject of pending.splice(0)) reject();
		},
	});
	return { make, asked, cancelled: () => cancelled };
}

const hosts = hostsOf(
	[
		"127.0.0.1 localhost",
		"::1 localhost",
		"# a comment",
		"10.0.0.7 Pinned.Example pinned-alias # trailing",
		"nonsense here",
		"fe80::1 pinned.example",
	].join("\n"),
);

describe("lookups by DNS in this process", () => {
	it("answers from the hosts file first, without case or the trailing dot, IPv4 before IPv6", async () => {
		const dns = tableResolver({});
		const pool = caresPool(4, { hosts, resolver: () => dns.make() });
		expect(await pool.run("pinned.example")?.answer).toEqual(["10.0.0.7", "fe80::1"]);
		expect(await pool.run("PINNED.example.", 4)?.answer).toEqual(["10.0.0.7"]);
		expect(await pool.run("pinned-alias")?.answer).toEqual(["10.0.0.7"]);
		expect(dns.asked).toEqual([]);
	});

	it("queries DNS absolute, A then AAAA for every family, A alone for IPv4", async () => {
		const dns = tableResolver({ "api.example.": { a: ["192.0.2.1"], aaaa: ["2001:db8::1"] } });
		const pool = caresPool(4, { hosts, resolver: () => dns.make() });
		expect(absolute("api.example")).toBe("api.example.");
		expect(absolute("api.example.")).toBe("api.example.");
		expect(await pool.run("api.example")?.answer).toEqual(["192.0.2.1", "2001:db8::1"]);
		expect(await pool.run("api.example.", 4)?.answer).toEqual(["192.0.2.1"]);
		expect(dns.asked).toEqual(["a api.example.", "aaaa api.example.", "a api.example."]);
	});

	it("answers one family's records where the other is absent, and fails where neither has any, or one family's query fails", async () => {
		const dns = tableResolver({
			"v4.example.": { a: ["192.0.2.4"] },
			"broken.example.": { error: "ESERVFAIL" },
		});
		const pool = caresPool(4, { hosts, resolver: () => dns.make() });
		expect(await pool.run("v4.example")?.answer).toEqual(["192.0.2.4"]);
		await expect(pool.run("none.example")?.answer).rejects.toMatchObject({ code: "ENOTFOUND" });
		await expect(pool.run("broken.example")?.answer).rejects.toMatchObject({ code: "ESERVFAIL" });
		// An A answered beside an AAAA that failed: never taken as the name's every address.
		const half: DnsResolver = {
			resolve4: async () => ["192.0.2.5"],
			resolve6: async () => Promise.reject(Object.assign(new Error("t"), { code: "ETIMEOUT" })),
			cancel: () => {},
		};
		const halfPool = caresPool(1, { hosts, resolver: () => half });
		await expect(halfPool.run("half.example")?.answer).rejects.toMatchObject({ code: "ETIMEOUT" });
		expect(await halfPool.run("half.example", 4)?.answer).toEqual(["192.0.2.5"]);
	});

	it("sends no single-label name the hosts file lacks: it fails as not found, never completed by a search list", async () => {
		const dns = tableResolver({ "short.": { a: ["192.0.2.9"] } });
		const pool = caresPool(4, { hosts, resolver: () => dns.make() });
		await expect(pool.run("short")?.answer).rejects.toMatchObject({ code: "ENOTFOUND" });
		await expect(pool.run("short.")?.answer).rejects.toMatchObject({ code: "ENOTFOUND" });
		// localhost answers only where the hosts file lists it.
		expect(await pool.run("localhost", 4)?.answer).toEqual(["127.0.0.1"]);
		expect(dns.asked).toEqual([]);
	});

	it("keeps a lookup another caller still needs when one caller's deadline passes, and cancels it once the last leaves", async () => {
		const dns = tableResolver({});
		const pool = caresPool(1, { hosts, resolver: () => dns.make(true) });
		const lookups = lookupsOver(pool);
		const first = new AbortController();
		const second = new AbortController();
		const one = lookups.resolve("shared.example", undefined, first.signal);
		const two = lookups.resolve("shared.example", undefined, second.signal);
		first.abort();
		await expect(one).rejects.toMatchObject({ failure: "timeout" });
		expect(dns.cancelled()).toBe(0);
		second.abort();
		await expect(two).rejects.toMatchObject({ failure: "timeout" });
		expect(dns.cancelled()).toBe(1);
		// Its place is free again.
		expect(pool.run("next.example")).toBeDefined();
	});

	it("fails a name of more addresses than a lookup takes (64), from DNS or the hosts file", async () => {
		const many = Array.from({ length: 65 }, (_, i) => `192.0.2.${i}`);
		const pool = caresPool(4, {
			hosts,
			resolver: () => tableResolver({ "many.example.": { a: many } }).make(),
		});
		await expect(pool.run("many.example", 4)?.answer).rejects.toThrow(/too many/);
		const listed = hostsOf(many.map((address) => `${address} listed.example`).join("\n"));
		const fromHosts = caresPool(4, { hosts: listed, resolver: () => tableResolver({}).make() });
		await expect(fromHosts.run("listed.example", 4)?.answer).rejects.toThrow(/too many/);
	});

	it("takes no place where its resolver cannot be made", () => {
		let fail = true;
		const pool = caresPool(1, {
			hosts,
			resolver: () => {
				if (fail) throw new Error("no resolver");
				return tableResolver({}).make();
			},
		});
		expect(() => pool.run("api.example")).toThrow("no resolver");
		fail = false;
		expect(pool.run("api.example")).toBeDefined();
	});

	it("asks DNS for a family the hosts file does not list a name for, as the system does", async () => {
		const dns = tableResolver({ "only6.example.": { a: ["192.0.2.6"] } });
		const pool = caresPool(4, {
			hosts: hostsOf("2001:db8::6 only6.example"),
			resolver: () => dns.make(),
		});
		expect(await pool.run("only6.example", 4)?.answer).toEqual(["192.0.2.6"]);
		expect(await pool.run("only6.example")?.answer).toEqual(["2001:db8::6"]);
		expect(dns.asked).toEqual(["a only6.example."]);
	});

	it("cancels a lookup its last waiter leaves, gives its place back at once, and is joined no more", async () => {
		const dns = tableResolver({});
		const pool = caresPool(1, { hosts, resolver: () => dns.make(true) });
		const job = pool.run("slow.example");
		if (!job) throw new Error("no job");
		expect(pool.run("other.example")).toBeUndefined();
		// A second waiter joins and leaves: the first still waits, nothing is cancelled.
		expect(job.want()).toBe(true);
		job.unwant();
		expect(dns.cancelled()).toBe(0);
		job.unwant();
		expect(dns.cancelled()).toBe(1);
		expect(job.want()).toBe(false);
		await expect(job.answer).rejects.toMatchObject({ code: "ECANCELLED" });
		expect(pool.run("other.example")).toBeDefined();
	});

	it("cancels the queries already sent where the last waiter leaves while DNS has not answered", async () => {
		const dns = tableResolver({});
		const pool = caresPool(1, { hosts, resolver: () => dns.make(true) });
		const job = pool.run("slow.example");
		if (!job) throw new Error("no job");
		// Let the lookup send its A and AAAA queries.
		await new Promise((sent) => setTimeout(sent, 0));
		expect(dns.asked).toEqual(["a slow.example.", "aaaa slow.example."]);
		job.unwant();
		await expect(job.answer).rejects.toMatchObject({ code: "ECANCELLED" });
		expect(dns.cancelled()).toBe(1);
		expect(pool.run("other.example")).toBeDefined();
	});
});

describe("the hosts file read", () => {
	it("merges a name's lines, keeps each family in the file's order, takes a scoped address, and skips what is no address", () => {
		const table = hostsOf(
			"10.0.0.1 a.example\n10.0.0.2 A.example.\nfe80::1%lo0 a.example\nbad a.example\n",
		);
		expect(table.get("a.example")).toEqual({ v4: ["10.0.0.1", "10.0.0.2"], v6: ["fe80::1%lo0"] });
	});

	it("reads at most 1 MiB of the hosts file: none there is empty, one unreadable or longer refused", async () => {
		const dir = await mkdtemp(join(tmpdir(), "hosts-"));
		try {
			const file = join(dir, "hosts");
			await writeFile(file, "10.0.0.1 a.example\n");
			expect(await readHostsFile(file)).toEqual({ text: "10.0.0.1 a.example\n" });
			expect(await readHostsFile(join(dir, "none"))).toEqual({ text: "" });
			expect(await readHostsFile(dir)).toEqual({
				refused: `the hosts file ${dir} could not be read`,
			});
			await writeFile(file, "#".repeat(hostsMaxBytes + 1));
			expect(await readHostsFile(file)).toEqual({
				refused: `the hosts file ${file} is over 1 MiB`,
			});
			await writeFile(file, "#".repeat(hostsMaxBytes));
			expect(await readHostsFile(file)).toMatchObject({ text: expect.any(String) });
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("counts the single-label names of the lists that the hosts file lacks, never one it lists, a dotted one or an address", () => {
		const lists = [
			{
				entries: ["redis", "pinned-alias", "api.example", "10.0.0.9", ".under.example"],
				port: false,
			},
			{ entries: ["ledger:9092", "keys.internal:8080"], port: true },
		];
		expect(unlistedShortNames(lists, hosts)).toBe(2);
	});
});

describe("a name queried absolute, under a search list (LOCALDOMAIN)", () => {
	// A DNS server on loopback answering short.corp.example alone, recording every query it is sent.
	const seen: string[] = [];
	const server = dgram.createSocket("udp4");
	let port = 0;
	const saved = process.env.LOCALDOMAIN;
	beforeAll(async () => {
		server.on("message", (query, from) => {
			const labels: string[] = [];
			let at = 12;
			while (query[at]) {
				const length = query[at] ?? 0;
				labels.push(query.subarray(at + 1, at + 1 + length).toString());
				at += length + 1;
			}
			const name = labels.join(".");
			const type = query.readUInt16BE(at + 1);
			seen.push(name);
			const hit = name === "svc.ns.corp.example" && type === 1;
			const head = Buffer.from(query.subarray(0, 12));
			head.writeUInt16BE(0x8180 | (hit ? 0 : 3), 2);
			head.writeUInt16BE(1, 4);
			head.writeUInt16BE(hit ? 1 : 0, 6);
			head.writeUInt32BE(0, 8);
			const answer = hit
				? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10])
				: Buffer.alloc(0);
			server.send(
				Buffer.concat([head, query.subarray(12, at + 5), answer]),
				from.port,
				from.address,
			);
		});
		await new Promise<void>((bound) => server.bind(0, "127.0.0.1", bound));
		port = (server.address() as { port: number }).port;
		// c-ares reads the search list from LOCALDOMAIN as each resolver is made.
		process.env.LOCALDOMAIN = "corp.example";
	});
	afterAll(() => {
		server.close();
		if (saved === undefined) delete process.env.LOCALDOMAIN;
		else process.env.LOCALDOMAIN = saved;
	});
	const pool = () =>
		caresPool(4, {
			hosts: hostsOf(""),
			resolver: () => {
				const resolver = new Resolver({ timeout: 500, tries: 1 });
				resolver.setServers([`127.0.0.1:${port}`]);
				return resolver;
			},
		});

	it("puts on the wire the name as given, under a search list: a short name fails as not found, never completed by it", async () => {
		seen.length = 0;
		// Two labels, as a Kubernetes service in its namespace: ndots would search it; absolute, it is not.
		await expect(pool().run("svc.ns", 4)?.answer).rejects.toThrow();
		expect(seen).not.toContain("svc.ns.corp.example");
		expect(seen).toEqual(["svc.ns"]);
		// One label is never sent at all.
		seen.length = 0;
		await expect(pool().run("svc", 4)?.answer).rejects.toThrow();
		expect(seen).toEqual([]);
	});

	it("resolves the name written fully qualified", async () => {
		expect(await pool().run("svc.ns.corp.example", 4)?.answer).toEqual(["192.0.2.10"]);
	});

	it("reaches the next nameserver past a dead first one within its timings (1 to 2 s measured)", async () => {
		const silent = dgram.createSocket("udp4");
		await new Promise<void>((bound) => silent.bind(0, "127.0.0.1", bound));
		try {
			const resolver = new Resolver(resolverTimings);
			resolver.setServers([
				`127.0.0.1:${(silent.address() as { port: number }).port}`,
				`127.0.0.1:${port}`,
			]);
			const begun = Date.now();
			const answer = await caresPool(1, { hosts: hostsOf(""), resolver: () => resolver }).run(
				"svc.ns.corp.example",
				4,
			)?.answer;
			expect(answer).toEqual(["192.0.2.10"]);
			expect(Date.now() - begun).toBeLessThan(3_000);
		} finally {
			silent.close();
		}
	}, 10_000);
});
