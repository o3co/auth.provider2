/** The Core's certificate and the authority of the Fronts' ones, as the paths of their PEM files. */
export interface CoreCertificates {
	readonly authority: string;
	readonly core: { readonly cert: string; readonly key: string };
}

/** For tests: the `core-wire` part of a test's configuration, the probe listener on any free port, unless the test sets its own. */
export function coreWireConfig(
	certificates: CoreCertificates,
	settings: Record<string, unknown> = {},
) {
	return {
		"core-wire": {
			"certificate-file": certificates.core.cert,
			"key-file": certificates.core.key,
			"front-authority-file": certificates.authority,
			"probe-port": 0,
			...settings,
		},
	};
}
