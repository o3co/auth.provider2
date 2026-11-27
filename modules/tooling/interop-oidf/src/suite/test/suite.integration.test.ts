import { X509Certificate } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { docker, dockerWithin } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import { certificateAt, requestJson } from "../../api/api.ts";
import { projectOf } from "../../compose/compose.ts";
import { hostForSuite, startSuite, suiteOrigin, suitePin } from "../suite.ts";

/** What Docker holds of a container, as `docker inspect` writes it. */
interface Inspected {
	readonly Config: {
		readonly Image: string;
		readonly Env: readonly string[];
		readonly Labels: Readonly<Record<string, string>>;
	};
}

/**
 * The suite at the repository's pin, started and stopped for real: Docker, `git`, `openssl` and
 * Python 3 on the path, and the network for its source and images. Run by hand, never by `pnpm check`.
 */
describe("the suite at its pin, on this machine", () => {
	it(
		"runs the pinned images as composed here, answers its API with the harness's certificate alone, and leaves nothing behind when stopped",
		async () => {
			const pin = await suitePin();
			const root = await mkdtemp(join(tmpdir(), "interop-oidf-suite-"));
			const dir = join(root, "suite");
			const project = `label=com.docker.compose.project=${projectOf(dir)}`;
			const tls = await selfSigned("localhost.emobix.co.uk", join(root, "tls"));
			const other = await selfSigned("localhost.emobix.co.uk", join(root, "other"));
			const suite = await startSuite(pin, dir, await hostForSuite(), join(root, "suite.log"), tls);
			try {
				expect(await suite.api("api/plan?length=1")).toBeTypeOf("object");
				const presented = await certificateAt();
				expect(new X509Certificate(presented).fingerprint256).toBe(
					new X509Certificate(tls.cert).fingerprint256,
				);
				// Another certificate naming the same host is no key to the suite.
				await expect(
					requestJson("GET", `${suiteOrigin}/api/plan?length=1`, other.cert),
				).rejects.toThrow();
				expect(existsSync(join(suite.scripts, "run-test-plan.py"))).toBe(true);
				// The images the override writes are the pinned file's: a pin bump that changes them fails here.
				const pinned = await readFile(
					join(dirname(suite.scripts), "docker-compose-prebuilt.yml"),
					"utf8",
				);
				for (const named of [
					`image: \${MONGODB_IMAGE:-mongo:6.0.13}`,
					`image: registry.gitlab.com/openid/conformance-suite/nginx:\${IMAGE_TAG`,
					`image: registry.gitlab.com/openid/conformance-suite:\${IMAGE_TAG`,
				])
					expect(pinned).toContain(named);
				expect(pinned.match(/^ {2}[a-z]+:$/gm)).toEqual(["  mongodb:", "  nginx:", "  server:"]);
				expect(await readFile(suite.certificate, "utf8")).toBe(tls.cert);
				// The runner's environment (vitest's `BASE_URL=/`) reached none of what the override writes.
				const ids = (
					await docker(["ps", "--quiet", "--filter", project], dockerWithin.control)
				).split("\n");
				const containers: Inspected[] = JSON.parse(
					await docker(["inspect", ...ids], dockerWithin.control),
				);
				const services = new Map(
					containers.map((c) => [c.Config.Labels["com.docker.compose.service"], c.Config]),
				);
				expect([...services.keys()].sort()).toEqual(["mongodb", "nginx", "server"]);
				for (const [service, config] of services)
					expect(config.Image, service).toEqual(
						service === "mongodb" ? "mongo:6.0.13" : expect.stringMatching(`:${pin.tag}$`),
					);
				expect(services.get("server")?.Env).toEqual(
					expect.arrayContaining([
						`BASE_URL=${suiteOrigin}`,
						"BASE_MTLS_URL=https://localhost.emobix.co.uk:8444",
						"SPRING_PROFILES_ACTIVE=dev",
					]),
				);
			} finally {
				await suite.stop();
			}
			expect(existsSync(dir)).toBe(false);
			for (const kind of [
				["ps", "--all"],
				["network", "ls"],
			]) {
				const left = await docker([...kind, "--quiet", "--filter", project], dockerWithin.control);
				expect(left, kind.join(" ")).toBe("");
			}
			expect(await readFile(join(root, "suite.log"), "utf8")).toContain("server");
		},
		20 * 60_000,
	);
});
