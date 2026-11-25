import type { Message } from "@mod/front-core-codec";
import type { WireCertificates } from "@mod/front-relay/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { assemble, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import coreWire from "../src/module.ts";
import { coreWireConfig } from "../src/testing.ts";

/** A Core of these modules behind core-wire, started, trusting the Fronts on localhost; its wire port, its probe port and its log. */
export async function core(
	certificates: WireCertificates,
	modules: readonly Module[],
	settings: Record<string, unknown> = {},
	httpSettings: Record<string, unknown> = { "trusted-proxies": ["127.0.0.1"] },
) {
	const recorded = recordingLog();
	const app = await assemble({
		modules: [http, tlsOptionsForTests, coreWire, ...modules],
		config: {
			...kernelConfig(),
			http: { port: 0, ...httpSettings },
			...coreWireConfig(certificates, settings),
		},
		runtime: quietRuntime({ log: recorded.log }),
	});
	await app.start();
	const probe = recorded.lines().find((l) => l.event === "core-wire.probe_listening");
	return {
		port: app.get(listening).port(),
		probePort: Number(probe?.fields?.port),
		lines: recorded.lines,
		stop: () => app.stop(1000),
	};
}

export const tokenMessage = (code = "abc", source = "203.0.113.5"): Message<"token"> => ({
	source,
	grantType: 1,
	code,
	redirectUri: "https://rp.example/cb",
	codeVerifier: "v".repeat(43),
	clientAssertionType: 1,
	clientAssertion: "a.b.c",
	clientId: "",
	authorizationDetails: 0,
	dpop: "d.e.f",
});
