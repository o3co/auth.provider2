/** The configuration a test gives a generated app, from each module's `./testing`, over the fakes of its outside systems. */
import { generateKeyPairSync } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { auditConfig } from "@mod/audit/testing";
import { auditHttpConfig } from "@mod/audit-http/testing";
import { authorizeConfig } from "@mod/authorize/testing";
import { publisherKey, signedBy } from "@mod/clients-registry/testing";
import { coreWireConfig } from "@mod/core-wire/testing";
import { dpopConfig } from "@mod/dpop/testing";
import { firstKeyConfig } from "@mod/first-key/testing";
import { httpConfig } from "@mod/http/testing";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig } from "@mod/kernel";
import { keysConfig } from "@mod/keys/testing";
import { tokensConfig } from "@mod/tokens/testing";
import { webauthnConfig } from "@mod/webauthn/testing";

/** The login screen's origin: the authorization's screen, WebAuthn's origin and RP id, the mail's link. */
const screen = "https://login.example.invalid";

/** A signed registry version in a file under `dir`, and the section reading it. */
export async function registryOf(dir: string) {
	const key = publisherKey();
	const file = join(dir, "clients.jws");
	const version = {
		v: 1,
		version: 1,
		issuedAt: 1_700_000_000,
		clients: [{ id: "rp-1", kind: "public", method: "none", sections: {} }],
	};
	await writeFile(file, `${signedBy(key, version)}\n`);
	return { "clients-registry": { file, "publisher-key": key.jwk, "min-version": 1 } };
}

/** What every Core of the patterns takes alike: its features' sections. */
const features = (origin: string) => ({
	...webauthnConfig({ "rp-id": new URL(screen).hostname, origins: [screen] }),
	...issuerConfig({ url: origin }),
	...authorizeConfig({ "screen-url": `${screen}/authorize` }),
	...firstKeyConfig({ "mail-link": `${screen}/first-key` }),
	...tokensConfig({ revocation: "denylist" }, { subjects: "checked" }),
	...dpopConfig({ nonce: { ...dpopConfig().dpop.nonce, required: "as" } }),
	"users-local": { "password-work": "scrypt:10,8,1,32,16" },
	"transparency-local": { origin: screen },
});

export interface CoreFakes {
	readonly port: number;
	readonly certificates: Parameters<typeof coreWireConfig>[0];
	readonly redis: number;
	readonly relay: number;
	readonly registry: Record<string, unknown>;
	readonly arn: (id: string) => string;
}

/** `nextgen-core`'s configuration over the fakes: the wire on `port`, Redis, the relay and the registry. */
export const coreConfig = (fakes: CoreFakes) => ({
	...kernelConfig(),
	...keysConfig(),
	"keys-kms": {
		region: "eu-west-1",
		keys: [
			{ kid: "test", "key-id": fakes.arn("authority") },
			{ kid: "core-test", "key-id": fakes.arn("core") },
			{ kid: "seal-test", "key-id": fakes.arn("sealing") },
		],
	},
	redis: {
		url: `redis://127.0.0.1:${fakes.redis}`,
		"accept-plaintext": true,
		replication: "none",
		authentication: "none",
	},
	"mail-smtp": {
		host: "127.0.0.1",
		port: fakes.relay,
		security: "none",
		from: "idp@example.invalid",
	},
	...auditConfig({ receivers: ["http"] }),
	...auditHttpConfig(),
	outbound: { allow: ["audit.example"] },
	...fakes.registry,
	...features("https://issuer.example.invalid"),
	...httpConfig({
		port: fakes.port,
		"public-origin": "https://issuer.example.invalid",
		"trusted-proxies": ["127.0.0.1"],
	}),
	...coreWireConfig(fakes.certificates),
});

const pem = () =>
	generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
		type: "pkcs8",
		format: "pem",
	});

/** `nextgen-dev`'s configuration: one process on loopback, its keys made here, the store in memory. */
export const devConfig = (fakes: {
	readonly port: number;
	readonly relay: number;
	readonly registry: Record<string, unknown>;
	readonly issuer: string;
}) => ({
	...kernelConfig(),
	kernel: { ...kernelConfig().kernel, environment: "development" },
	...keysConfig(),
	"keys-local": { keys: ["test", "core-test", "seal-test"].map((kid) => ({ kid, pem: pem() })) },
	store: { "accept-volatile": true, "accept-unauthenticated": true },
	"mail-smtp": {
		host: "127.0.0.1",
		port: fakes.relay,
		security: "none",
		from: "idp@example.invalid",
	},
	...auditConfig({ receivers: ["stdout"] }),
	...fakes.registry,
	...features(fakes.issuer),
	...httpConfig({
		port: fakes.port,
		"public-origin": `http://127.0.0.1:${fakes.port}`,
		"insecure-origin": true,
	}),
});
