import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { assemble, type BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { issuer, type MetadataItem, metadata } from "../src/contract.ts";
import issuerModule from "../src/module.ts";
import { issuerConfig } from "../src/testing.ts";

const httpServer = testServer();

/** The Front's origin, where the endpoints are, apart from the issuer's own. */
const front = "https://front.example";

const boot = (
	url: unknown,
	/** None where the test writes no public origin. */
	origin: string | null = front,
	environment: "production" | "development" = "production",
) =>
	assemble({
		modules: [http, httpServer, issuerModule],
		config: {
			...kernelConfig({ environment }),
			...httpConfig(
				origin
					? {
							"public-origin": origin,
							...(origin.startsWith("http:") ? { "insecure-origin": true } : {}),
						}
					: {},
			),
			issuer: { url },
		},
	});
const refusedAt = async (run: Promise<unknown>) =>
	((await run.catch((error) => error)) as BootRefused).refusals?.map((r) => r.where);

it("names this provider by the configured URL, as written, frozen", async () => {
	const app = await boot("https://issuer.example/tenant");
	expect(app.get(issuer).url).toBe("https://issuer.example/tenant");
	expect(Object.isFrozen(app.get(issuer))).toBe(true);
});

it("builds a test configuration on https://issuer.example by default", async () => {
	const built = await assemble({
		modules: [http, httpServer, issuerModule],
		config: { ...kernelConfig(), ...httpConfig({ "public-origin": front }), ...issuerConfig() },
	});
	expect(built.get(issuer).url).toBe("https://issuer.example");
});

it("refuses an issuer URL the section does not take, as written [oidc-discovery-3-a] [rfc8414-2-a] [rfc9207-2-b]", async () => {
	const refused: Record<string, unknown> = {
		"another scheme": "ftp://issuer.example",
		"a trailing /": "https://issuer.example/",
		"not a URL": "not a url",
		missing: undefined,
		"a query": "https://issuer.example?tenant=a",
		"a fragment": "https://issuer.example#a",
		userinfo: "https://user@issuer.example",
		"an upper-case scheme": "HTTPS://issuer.example",
	};
	for (const [name, url] of Object.entries(refused)) {
		expect(await refusedAt(boot(url)), name).toEqual(["issuer.url"]);
	}
});

it("takes an issuer on its own static origin, apart from the public origin or on it, with a path or none", async () => {
	expect((await boot("https://issuer.example", "https://other.example")).get(issuer).url).toBe(
		"https://issuer.example",
	);
	expect((await boot("https://as.example/t", "https://as.example")).get(issuer).url).toBe(
		"https://as.example/t",
	);
});

it("names its endpoints on http's public origin, the Front's, whatever the issuer's origin", async () => {
	const apart = (await boot("https://issuer.example/t", "https://front.example")).get(issuer);
	expect(apart.endpointOrigin).toBe("https://front.example");
	const same = (await boot("https://as.example/t", "https://as.example")).get(issuer);
	expect(same.endpointOrigin).toBe("https://as.example");
});

it("refuses boot where http's public origin is not written, as no endpoint has an origin then, saying to write it", async () => {
	const refused = await boot("https://issuer.example", null).catch(
		(error: BootRefused) => error.refusals,
	);
	expect(refused).toEqual([
		{
			where: "http.public-origin",
			reason:
				"issuer names the endpoints on http.public-origin: write the origin the Front is reached at",
		},
	]);
});

it("collects the items this server names itself by, refusing two contributions of one item or one of the issuer item", async () => {
	const named = contract<readonly MetadataItem[]>("named");
	const item = (module: string, name: string, value: unknown) =>
		defineModule({ name: module, replicaSafe: true, takes: [] }, (m) => [
			m.contribute(metadata).by(() => ({ name, value })),
		]);
	const reader = defineModule({ name: "reader", replicaSafe: true, takes: [metadata] }, (m) => [
		m.provide(named).by((c) => c.collect(metadata)),
	]);
	const bootWith = (...modules: ReturnType<typeof item>[]) =>
		assemble({
			modules: [http, httpServer, issuerModule, ...modules],
			config: { ...kernelConfig(), ...httpConfig({ "public-origin": front }), ...issuerConfig() },
		});
	const app = await bootWith(
		item("a", "a_endpoint", "https://issuer.example/a"),
		item("b", "b", undefined),
		reader,
	);
	expect(app.get(named)).toEqual([
		{ name: "a_endpoint", value: "https://issuer.example/a" },
		{ name: "b", value: undefined },
	]);
	expect(await refusedAt(bootWith(item("a", "same", 1), item("b", "same", 2)))).toEqual([
		"issuer.metadata:same",
	]);
	// The issuer item is the configured URL, refused whether or not anyone reads the items.
	for (const value of ["https://elsewhere.example", undefined]) {
		expect(await refusedAt(bootWith(item("a", "issuer", value)))).toEqual([
			"issuer.metadata:issuer",
		]);
	}
});

it("takes all it names, with a public origin on the issuer's origin and on another", async () => {
	for (const origin of [
		{ "public-origin": "https://issuer.example" },
		{ "public-origin": front },
	]) {
		const input = {
			modules: [http, httpServer, issuerModule],
			config: { ...kernelConfig(), ...httpConfig(origin), ...issuerConfig() },
		};
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["issuer"], JSON.stringify(origin)).toBeUndefined();
	}
});

it("takes a plain-http issuer only beside a plain-http public origin, which http takes only when told", async () => {
	const refused = await boot("http://issuer.example", front, "development").catch(
		(error: BootRefused) => error.refusals,
	);
	expect(refused).toEqual([
		{
			where: "issuer.url",
			reason:
				"a plain-http issuer needs a plain-http public origin, accepted by http.insecure-origin",
		},
	]);
	const plain = await boot("http://as.example", "http://front.example", "development");
	expect(plain.get(issuer).url).toBe("http://as.example");
});

it("refuses a plain-http issuer in a production deployment [oidc-discovery-3-a] [rfc8414-2-a] [rfc8414-3-b] [rfc9207-2-b]", async () => {
	const refused = await boot("http://as.example", "http://as.example").catch(
		(error: BootRefused) => error.refusals,
	);
	expect(refused).toContainEqual({
		where: "issuer.url",
		reason:
			"is plain http, which a production deployment does not take; set kernel.environment = development to try one",
	});
});
