import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

/** A certificate and its key, as the paths of their PEM files. */
export interface CertificateFiles {
	readonly cert: string;
	readonly key: string;
}

/**
 * For tests: the wire's certificates, made by openssl (on the path) once for the process: an
 * authority, the Core's certificate for `localhost` and 127.0.0.1, a Front instance's
 * (`spiffe://auth.test/front/1`), another's (`spiffe://auth.test/front/2`) and one naming no URI,
 * each from it, and a stranger's, from an authority of its own. `remove` deletes them.
 */
export interface WireCertificates {
	readonly authority: string;
	readonly core: CertificateFiles;
	readonly front: CertificateFiles;
	readonly otherFront: CertificateFiles;
	/** A Front's certificate from the authority naming no URI, only a DNS name and its CN. */
	readonly unnamedFront: CertificateFiles;
	readonly stranger: CertificateFiles;
	remove(): Promise<void>;
}

const run = (args: readonly string[]) =>
	promisify(execFile)("openssl", [...args], { timeout: 30_000, killSignal: "SIGKILL" });
const p256 = [
	"-newkey",
	"ec",
	"-pkeyopt",
	"ec_paramgen_curve:P-256",
	"-pkeyopt",
	"ec_param_enc:named_curve",
	"-nodes",
	"-sha256",
];

async function authority(dir: string, name: string): Promise<CertificateFiles> {
	const files = { cert: join(dir, `${name}.pem`), key: join(dir, `${name}.key`) };
	await run([
		"req",
		"-x509",
		...p256,
		"-days",
		"2",
		"-subj",
		`/CN=${name}`,
		"-keyout",
		files.key,
		"-out",
		files.cert,
	]);
	return files;
}

async function issued(
	dir: string,
	name: string,
	by: CertificateFiles,
	altNames: string,
): Promise<CertificateFiles> {
	const files = { cert: join(dir, `${name}.pem`), key: join(dir, `${name}.key`) };
	const csr = join(dir, `${name}.csr`);
	const ext = join(dir, `${name}.ext`);
	await writeFile(ext, `subjectAltName=${altNames}\n`);
	await run(["req", "-new", ...p256, "-subj", `/CN=${name}`, "-keyout", files.key, "-out", csr]);
	await run([
		"x509",
		"-req",
		"-in",
		csr,
		"-CA",
		by.cert,
		"-CAkey",
		by.key,
		"-CAcreateserial",
		"-sha256",
		"-days",
		"2",
		"-extfile",
		ext,
		"-out",
		files.cert,
	]);
	return files;
}

let made: Promise<WireCertificates> | undefined;

export function wireCertificates(): Promise<WireCertificates> {
	made ??= (async () => {
		const dir = await mkdtemp(join(tmpdir(), "front-relay-"));
		const ca = await authority(dir, "authority");
		const other = await authority(dir, "other-authority");
		return {
			authority: ca.cert,
			core: await issued(dir, "core", ca, "DNS:localhost,IP:127.0.0.1"),
			front: await issued(dir, "front", ca, "URI:spiffe://auth.test/front/1"),
			otherFront: await issued(dir, "other-front", ca, "URI:spiffe://auth.test/front/2"),
			unnamedFront: await issued(dir, "unnamed-front", ca, "DNS:front.auth.test"),
			stranger: await issued(dir, "stranger", other, "URI:spiffe://auth.test/front/9"),
			remove: () => {
				made = undefined;
				return rm(dir, { recursive: true, force: true });
			},
		};
	})();
	return made;
}

/** For tests: the `front-relay` part of a test's configuration, the Front's certificate from `wireCertificates`, unless the test sets its own. */
export function frontRelayConfig(
	certificates: WireCertificates,
	settings: Record<string, unknown> = {},
) {
	return {
		"front-relay": {
			"core-host": "127.0.0.1",
			"certificate-file": certificates.front.cert,
			"key-file": certificates.front.key,
			"core-authority-file": certificates.authority,
			...settings,
		},
	};
}
