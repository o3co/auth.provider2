import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { composeOverride, projectOf } from "../compose.ts";

const composed = {
	tag: "release-v1.2.3",
	origins: { base: "https://suite.test:8443", mtls: "https://suite.test:8444" },
	tls: { cert: "/run/nginx-cert.pem", key: "/run/nginx-key.pem" },
};

describe("the compose file beside the suite's own", () => {
	it("lets the suite's server reach this machine by name, in IPv4 alone", () => {
		const linux = composeOverride({ name: "host.docker.internal", mapped: "172.17.0.1" }, composed);
		expect(linux).toContain('    extra_hosts:\n      - "host.docker.internal:172.17.0.1"\n');
		expect(linux).not.toContain("host-gateway");
		// Docker Desktop names the machine itself.
		expect(composeOverride({ name: "host.docker.internal" }, composed)).not.toContain(
			"extra_hosts",
		);
	});

	it("keeps the suite's store in memory, never in a directory of this machine", () => {
		for (const host of [{ name: "h" }, { name: "h", mapped: "1.2.3.4" }]) {
			expect(composeOverride(host, composed)).toMatch(
				/^services:\n {2}mongodb:\n {4}image: mongo:6\.0\.13\n {4}volumes:\n {6}- type: tmpfs\n {8}target: \/data\/db\n/,
			);
		}
	});

	it("names the images at the pinned tag and the suite's origins itself, whatever the runner's environment holds", () => {
		const before = { base: process.env.BASE_URL, tag: process.env.IMAGE_TAG };
		process.env.BASE_URL = "/";
		process.env.IMAGE_TAG = "latest";
		try {
			const text = composeOverride({ name: "h" }, composed);
			expect(text).toContain(
				"  nginx:\n    image: registry.gitlab.com/openid/conformance-suite/nginx:release-v1.2.3\n",
			);
			expect(text).toContain(
				"  server:\n    image: registry.gitlab.com/openid/conformance-suite:release-v1.2.3\n    environment:\n      BASE_URL: https://suite.test:8443\n      BASE_MTLS_URL: https://suite.test:8444\n",
			);
			expect(text).toContain("  mongodb:\n    image: mongo:6.0.13\n");
			expect(text).toContain("      SPRING_PROFILES_ACTIVE: dev\n");
			expect(text).not.toContain("${");
			expect(text).not.toContain("latest");
		} finally {
			for (const [name, value] of [
				["BASE_URL", before.base],
				["IMAGE_TAG", before.tag],
			] as const) {
				if (value === undefined) delete process.env[name];
				else process.env[name] = value;
			}
		}
	});

	it("has the suite's nginx answer with the harness's certificate, read only", () => {
		const text = composeOverride({ name: "h" }, composed);
		expect(text).toContain(
			'    volumes:\n      - type: bind\n        source: "/run/nginx-cert.pem"\n        target: /etc/ssl/certs/nginx-selfsigned.crt\n        read_only: true\n',
		);
		expect(text).toContain(
			'        source: "/run/nginx-key.pem"\n        target: /etc/ssl/private/nginx-selfsigned.key\n        read_only: true\n',
		);
	});

	it("writes the certificate's paths as YAML strings Compose interpolates nothing in", () => {
		const text = composeOverride(
			{ name: "h" },
			{ ...composed, tls: { cert: "/run/a $HOME #x: y/cert.pem", key: '/run/"k"/key.pem' } },
		);
		expect(text).toContain('        source: "/run/a $$HOME #x: y/cert.pem"\n');
		expect(text).toContain('        source: "/run/\\"k\\"/key.pem"\n');
	});

	it("marks every container with the process that owns it", () => {
		const text = composeOverride({ name: "h", mapped: "1.2.3.4" }, { ...composed, owner: 4242 });
		for (const service of ["mongodb", "nginx", "server"]) {
			expect(text).toMatch(
				new RegExp(
					`  ${service}:\\n(    .*\\n|      .*\\n)*    labels:\\n      o3co.oidf.owner: "4242"\\n`,
				),
			);
		}
		expect(composeOverride({ name: "h" }, composed)).toContain(`o3co.oidf.owner: "${process.pid}"`);
	});

	it("gives each start a Compose project of its own, though every start's directory is named alike", () => {
		const one = projectOf(join("/tmp/interop-oidf-fapi-a1", "suite"));
		const other = projectOf(join("/tmp/interop-oidf-fapi-b2", "suite"));
		expect(one).not.toBe(other);
		for (const name of [one, other]) expect(name).toMatch(/^o3co-oidf-[a-z0-9]+$/);
	});
});
