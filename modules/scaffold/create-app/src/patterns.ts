/** The three patterns: each names every axis it composes, the promises it requires and the companions it runs. */

/** A pattern: what it composes and requires, and its card's text for the app's guide. */
export interface Pattern {
	readonly name: string;
	readonly use: string;
	readonly features: readonly string[];
	/** Each axis's choice, by owner: every axis the pattern composes is named. */
	readonly axes: Readonly<Record<string, string>>;
	/** What no feature reaches, composed beside the features (the Front's relay). */
	readonly add: readonly string[];
	/** The promises the app requires: the one value a pattern writes, in `promises.required`. */
	readonly required: readonly string[];
	readonly companions: readonly string[];
	readonly card: string;
}

const scoped = (names: readonly string[]) => names.map((name) => `@mod/${name}`);
const axesOf = (axes: Readonly<Record<string, string>>) =>
	Object.fromEntries(
		Object.entries(axes).map(([owner, choice]) => [`@mod/${owner}`, `@mod/${choice}`]),
	);

/** The Core's features: client-credentials, userinfo, introspection and sign-up are added by the operator (V21, V27). */
const coreFeatures = scoped([
	"authorize",
	"par",
	"dpop",
	"approvals",
	"passkeys",
	"passkey-management",
	"first-key",
	"authorize-claims",
	"resource-indicators",
	"discovery",
	"oidc",
]);

export const patterns: readonly Pattern[] = [
	{
		name: "nextgen-front",
		use: "The Front: the browser's and the RP's entrance, relaying each request to the Core over the wire. It holds no key, no log, no store and no authentication.",
		features: scoped(["http-ops"]),
		axes: axesOf({ http: "front-relay", metrics: "metrics-prometheus" }),
		add: scoped(["front-relay"]),
		required: [],
		companions: [],
		card: "Run one or more instances apart from the Core, each reaching only the Core's entrance (`front-relay.core-host`, `front-relay.core-port`); its certificate chains to the authorities the Core takes (`core-wire.front-authority-file`).",
	},
	{
		name: "nextgen-core",
		use: "The Core: authentication, tokens and keys, reached by the Fronts over the wire alone.",
		features: coreFeatures,
		axes: axesOf({
			http: "core-wire",
			metrics: "metrics-log",
			keys: "keys-kms",
			transparency: "transparency-local",
			store: "redis",
			mail: "mail-smtp",
			users: "users-local",
			audit: "audit-http",
			clients: "clients-registry",
		}),
		add: [],
		required: ["front-compromise-new-authorization", "front-compromise-client-token"],
		companions: [],
		card: [
			"It requires the two promises a compromised Front must not break; boot is refused where one does not hold, so changing `http` (`--axis http=in-process`) gives an app that never boots.",
			"Setup, in order: the KMS keys and the Core's role (`keys-kms`); the wire's certificates (`core-wire`); the signed client registry (`clients-registry`, signed with `registry-sign`); the mail relay (`mail-smtp`); Redis and its statement (`redis`); then publish the discovery document and the key sets for the publisher (`discovery-publish`, `keys-publish`).",
			"Not composed unless added: `client-credentials` (`--add client-credentials`; then requiring `no-client-subject-token` is recommended only where no machine client is registered), `sign-up` (`--add sign-up`: a user with no passkey is then created, not refused), `userinfo`. An outside ledger: `--axis users=users-http --add passkey-witness-http` (its passkey witness beside it), each with its own section and the ledger's host in `outbound.allow`.",
			"`transparency-local` is not recommended: see its line under the setup below.",
		].join("\n\n"),
	},
	{
		name: "nextgen-dev",
		use: "The Front and the Core in one process, for development and trials on one machine. It requires no promise: in one process, a compromised Front is a compromised Core.",
		features: coreFeatures,
		axes: axesOf({
			http: "in-process",
			metrics: "metrics-prometheus",
			keys: "keys-local",
			transparency: "transparency-local",
			store: "store",
			mail: "mail-smtp",
			users: "users-local",
			audit: "audit-stdout",
			clients: "clients-registry",
		}),
		add: [],
		required: [],
		companions: scoped(["publish-serve", "registry-sign"]),
		card: [
			"Setup, in order: three keys for `keys-local`; a client registry signed with `pnpm registry-sign`; a mail relay on this machine for `mail-smtp` (`mail-smtp.host`, `mail-smtp.security = none`); `kernel.environment = development` with `http.insecure-origin = true` and a plain `http://` `http.public-origin` on loopback.",
			"The issuer (`issuer.url`) is the publisher's origin: a loopback origin of its own, another port than `http.port`. Publish with `pnpm discovery-publish <directory>` and `pnpm keys-publish <directory><the issuer's path>`, then serve them with `pnpm publish-serve <directory> <the issuer's origin> <http.public-origin>`: the same origin as `issuer.url`, and the login screen's origin as the one page let read them.",
		].join("\n\n"),
	},
];

export const patternNamed = (name: string) => patterns.find((p) => p.name === name);
