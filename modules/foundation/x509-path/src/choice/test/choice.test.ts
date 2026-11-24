import { X509Certificate } from "node:crypto";
import { getCACertificates } from "node:tls";
import { describe, expect, it, type MockInstance, vi } from "vitest";
import { type Issued, issue } from "../../testing.ts";
import { chosen, trustOf } from "../choice.ts";

/** What a choice gives, as its kind and the CNs of the chain chosen, by their DER. */
const pickOf = (leaf: Issued, sent: readonly Issued[], anchors: readonly Issued[], depth = 4) => {
	const trust = trustOf({ anchors: anchors.map((a) => a.der), selfSignedAnchorsOnly: false });
	const picked = chosen(
		leaf.der,
		sent.map((s) => s.der),
		trust,
		depth,
	);
	if (picked.kind !== "chain") return picked.kind;
	return picked.chain
		.map((der) => new X509Certificate(der).subject.replace(/^CN=/, ""))
		.join(" > ");
};
/**
 * A choice's work, whatever the clock: how many times it asks node whether one certificate issued
 * another, how many of those asked a pair asked before, how many certificates asked (those it
 * entered), and how many signatures it verifies.
 */
function counted<T>(run: () => T) {
	const spies: MockInstance[] = [];
	try {
		const asked = vi.spyOn(X509Certificate.prototype, "checkIssued");
		spies.push(asked);
		const verified = vi.spyOn(X509Certificate.prototype, "verify");
		spies.push(verified);
		const value = run();
		const asking = asked.mock.contexts.map((one) => (one as X509Certificate).fingerprint256);
		// Each pair by the fingerprints of the certificate asking and the one it asks of.
		const pairs = asked.mock.calls.map(([issuer], i) => `${asking[i]}>${issuer.fingerprint256}`);
		const again = pairs.length - new Set(pairs).size;
		const entered = new Set(asking).size;
		return { value, asked: pairs.length, again, entered, verified: verified.mock.calls.length };
	} finally {
		for (const spy of spies) spy.mockRestore();
	}
}
/** The most a choice entering this many certificates asks: each asks every one sent and trusted once. */
const mostAsked = (entered: number, sent: number, trusted: number) => entered * (sent + trusted);

/** One signed as `cn` by keys whose issuer is named `issuerCn`, as a peer could make them. */
const signedBy = (cn: string, issuerCn: string, by: Issued, more = {}) =>
	issue({ cn, by: { ...by, cn: issuerCn }, ca: true, ...more });

describe("choosing a path", () => {
	it("takes no edge node does not read as issued, though its key identifier and signature match: a self-issued one named apart", async () => {
		const root = await issue({ cn: "B", ca: true, keyIds: true });
		// Subject and issuer "A", its key identifier B's, signed by B: node's checkIssued says no.
		const posing = await issue({ cn: "A", issuerName: "A", by: root, ca: true, keyIds: true });
		const leaf = await issue({ cn: "leaf", by: posing, keyIds: true });
		expect(pickOf(leaf, [posing], [root])).toBe("path");
		const named = await issue({ cn: "A", by: root, ca: true, keyIds: true });
		const under = await issue({ cn: "leaf", by: named, keyIds: true });
		expect(pickOf(under, [named], [root])).toBe("leaf > A > B");
	});

	it("finds an anchor without key identifiers whose name is written in another string type than the name below it gives", async () => {
		// The root's name a PrintableString, its intermediate's issuer name a UTF8String: node takes them as one.
		const root = await issue({ cn: "R", ca: true, printableSubject: true });
		const intermediate = await issue({ cn: "I", by: root, ca: true });
		const leaf = await issue({ cn: "leaf", by: intermediate });
		expect(pickOf(leaf, [intermediate], [root])).toBe("leaf > I > R");
		// A name that differs is still no issuer's.
		const other = await issue({ cn: "Q", by: { ...root, cn: "Q" }, ca: true });
		expect(pickOf(await issue({ cn: "leaf", by: other }), [other], [root])).toBe("path");
	});

	it("ends on a cycle of two issuers with no anchor, and takes the root a cycle also reaches", async () => {
		const root = await issue({ cn: "R", ca: true });
		const y = await issue({ cn: "Y", ca: true });
		const x = await signedBy("X", "Y", y);
		const yByX = await signedBy("Y", "X", { ...x, keys: x.keys });
		const leaf = await issue({ cn: "leaf", by: x });
		const cycle = counted(() => pickOf(leaf, [x, yByX], [root]));
		expect(cycle.value).toBe("path");
		// The leaf, X and Y entered, each asking the two sent and the one root once at most.
		expect(cycle.asked).toBeLessThanOrEqual(mostAsked(3, 2, 1));
		expect(cycle.again).toBe(0);
		const yByRoot = await signedBy("Y", "R", root, { keys: y.keys });
		expect(pickOf(leaf, [x, yByX, yByRoot], [root])).toBe("leaf > X > Y > R");
	});

	it("takes no certificate with more than four issuers, nor more than ten sent, or the intermediates allowed and one more", async () => {
		const root = await issue({ cn: "R", ca: true });
		const first = await issue({ cn: "I", by: root, ca: true });
		const leaf = await issue({ cn: "leaf", by: first });
		// The same issuer, name and key, issued again: each an edge.
		const again = (n: number) =>
			Promise.all(
				Array.from({ length: n }, () => issue({ cn: "I", by: root, ca: true, keys: first.keys })),
			);
		expect(pickOf(leaf, [first, ...(await again(3))], [root])).toBe("leaf > I > R");
		expect(pickOf(leaf, [first, ...(await again(4))], [root])).toBe("path");
		const padding = await Promise.all(Array.from({ length: 10 }, (_, n) => issue({ cn: `p${n}` })));
		expect(pickOf(leaf, [first, ...padding], [root])).toBe("path");
		// With 14 intermediates allowed, a peer may send 15.
		const extra = await Promise.all(Array.from({ length: 4 }, (_, n) => issue({ cn: `q${n}` })));
		const fifteen = [first, ...padding, ...extra];
		expect(pickOf(leaf, fifteen, [root], 14)).toBe("leaf > I > R");
		expect(pickOf(leaf, [...fifteen, await issue({ cn: "q4" })], [root], 14)).toBe("path");
		for (const allowed of [15, -1, 1.5])
			expect(() => pickOf(leaf, [], [root], allowed)).toThrow(TypeError);
	});

	it("goes on past an intermediate the trust holds to its root, and tells a path past the intermediates allowed", async () => {
		const root = await issue({ cn: "R", ca: true });
		const held = await issue({ cn: "I", by: root, ca: true });
		const leaf = await issue({ cn: "leaf", by: held });
		const trust = trustOf({
			anchors: [root.der],
			intermediates: [held.der],
			selfSignedAnchorsOnly: true,
		});
		const picked = chosen(leaf.der, [], trust, 4);
		expect(picked.kind === "chain" && picked.chain.length).toBe(3);
		// Sent and held both, found by its key identifier and by its name: asked once all the same.
		const keyed = await issue({ cn: "K", by: root, ca: true, keyIds: true });
		const under = await issue({ cn: "leaf", by: keyed, keyIds: true });
		const both = trustOf({
			anchors: [root.der],
			intermediates: [keyed.der],
			selfSignedAnchorsOnly: true,
		});
		const once = counted(() => chosen(under.der, [keyed.der, keyed.der], both, 4));
		expect(once.value.kind).toBe("chain");
		expect(once.again).toBe(0);
		expect(chosen(leaf.der, [], trust, 0)).toEqual({ kind: "too many intermediates" });
	});

	it("enters at most 32 certificates, the leaf among them, however far the trust's issuers branch", async () => {
		// Nine levels of four certificates each, every one of a level issuing every one below it.
		const bases = await Promise.all(
			Array.from({ length: 10 }, (_, k) => issue({ cn: `M${k}`, ca: true })),
		);
		const level = (k: number) =>
			Promise.all(
				Array.from({ length: 4 }, () =>
					signedBy(`M${k}`, `M${k + 1}`, bases[k + 1] as Issued, {
						keys: (bases[k] as Issued).keys,
					}),
				),
			);
		const held = (await Promise.all(Array.from({ length: 9 }, (_, k) => level(k)))).flat();
		const root = await issue({ cn: "R", ca: true });
		const trust = trustOf({
			anchors: [root.der],
			intermediates: held.map((one) => one.der),
			selfSignedAnchorsOnly: true,
		});
		const leaf = await issue({ cn: "leaf", by: { ...(bases[0] as Issued), cn: "M0" } });
		const work = counted(() => chosen(leaf.der, [], trust, 14));
		expect(work.value).toEqual({ kind: "path" });
		// The leaf and 36 held could be entered; the choice stops at 32.
		expect(work.entered).toBeLessThanOrEqual(32);
		expect(work.asked).toBeLessThanOrEqual(mostAsked(32, 0, held.length + 1));
		expect(work.again).toBe(0);
	});

	it("finds no path for a leaf that is itself an anchor, as the engine alone found none before", async () => {
		const pinned = await issue({ cn: "client" });
		expect(pickOf(pinned, [], [pinned])).toBe("path");
	});

	it("refuses, asked for self-signed anchors alone, one that is not", async () => {
		const root = await issue({ cn: "R", ca: true });
		const held = await issue({ cn: "I", by: root, ca: true });
		expect(() => trustOf({ anchors: [held.der], selfSignedAnchorsOnly: true })).toThrow(TypeError);
		expect(() => trustOf({ anchors: [held.der], selfSignedAnchorsOnly: false })).not.toThrow();
		expect(() =>
			trustOf({ anchors: [new Uint8Array([1, 2])], selfSignedAnchorsOnly: false }),
		).toThrow(TypeError);
	});
});

describe("a choice's cost, against the platform's store and one root more", () => {
	it("chooses an ordinary chain, a full budget, the most a peer may send and a cycle each within its bound of work, and logs how long", async () => {
		const extra = await issue({ cn: "extra root", ca: true });
		const store = getCACertificates("default").map((pem) => new X509Certificate(pem));
		const selfSigned = store.filter((c) => c.checkIssued(c) && c.verify(c.publicKey));
		const trust = trustOf({
			anchors: [...selfSigned.map((c) => new Uint8Array(c.raw)), extra.der],
			intermediates: store.filter((c) => !selfSigned.includes(c)).map((c) => new Uint8Array(c.raw)),
			selfSignedAnchorsOnly: true,
		});
		const trusted = store.length + 1;
		/**
		 * The choice's kind, its work held to the bound for the certificates it enters, and how long it
		 * takes, logged alone: the clock is the machine's.
		 */
		const timed = (
			leaf: Issued,
			sent: readonly Issued[],
			{ entered, verifies }: { readonly entered: number; readonly verifies: number },
			depth = 6,
		) => {
			const choose = () =>
				chosen(
					leaf.der,
					sent.map((s) => s.der),
					trust,
					depth,
				);
			const work = counted(choose);
			expect(work.entered).toBeLessThanOrEqual(entered);
			expect(work.asked).toBeLessThanOrEqual(mostAsked(entered, sent.length, trusted));
			expect(work.again).toBe(0);
			// A signature is verified only where node takes the certificate as the issuer, once each.
			expect(work.verified).toBeLessThanOrEqual(verifies);
			const runs = 20;
			const started = performance.now();
			for (let run = 0; run < runs; run++) choose();
			const ms = (performance.now() - started) / runs;
			return { kind: work.value.kind, asked: work.asked, ms };
		};
		// Ordinary: a leaf under two intermediates under the root.
		const a = await issue({ cn: "a", by: extra, ca: true });
		const b = await issue({ cn: "b", by: a, ca: true });
		const leaf = await issue({ cn: "leaf", by: b });
		// The leaf, b and a entered.
		const ordinary = timed(leaf, [b, a], { entered: 3, verifies: 3 });
		// Full: four issuers at each step, no anchor reached, ten sent.
		const top = await issue({ cn: "top", ca: true });
		const levels = [
			await Promise.all(
				Array.from({ length: 4 }, () => issue({ cn: "m", by: top, ca: true, keys: top.keys })),
			),
		];
		const wide = levels[0] as Issued[];
		const under = await issue({ cn: "leaf", by: wide[0] as Issued });
		const sentWide = [
			...wide,
			...(await Promise.all(Array.from({ length: 6 }, (_, n) => issue({ cn: `w${n}`, ca: true })))),
		];
		// The leaf and the four issuers entered.
		const full = timed(under, sentWide, { entered: 5, verifies: 4 });
		// The most a peer may send: fifteen under fourteen intermediates allowed, a chain to no anchor,
		// so every step finds no issuer in the index and asks the whole store.
		const deep: Issued[] = [await issue({ cn: "d14", ca: true })];
		for (let n = 13; n >= 0; n--) {
			deep.unshift(await issue({ cn: `d${n}`, by: deep[0] as Issued, ca: true }));
		}
		// The leaf and fourteen intermediates entered.
		const deepest = timed(
			await issue({ cn: "leaf", by: deep[0] as Issued }),
			deep,
			{ entered: 15, verifies: 15 },
			14,
		);
		// A cycle of two.
		const y = await issue({ cn: "Y", ca: true });
		const x = await signedBy("X", "Y", y);
		const yByX = await signedBy("Y", "X", { ...x, keys: x.keys });
		const cycled = await issue({ cn: "leaf", by: x });
		// The leaf, X and Y entered.
		const cycle = timed(cycled, [x, yByX], { entered: 3, verifies: 3 });
		console.log(JSON.stringify({ store: store.length, ordinary, full, deepest, cycle }));
		expect([ordinary.kind, full.kind, deepest.kind, cycle.kind]).toEqual([
			"chain",
			"path",
			"too many intermediates",
			"path",
		]);
	});
});
