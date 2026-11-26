import { contract, extensionPoint } from "@mod/kernel";

/** The promises a deployment's judgment names, each one word; this module owns the words. */
export const promiseNames = Object.freeze({
	/** A new login needs the user's passkey, even when the Front is compromised (with the session's binding). */
	newAuthorization: "front-compromise-new-authorization",
	/** A client's token needs the client's private key, even when the Front is compromised. */
	clientToken: "front-compromise-client-token",
	/** A write to the store that the Core did not make is told apart. */
	storeWrite: "store-write",
	/** A compromised Core's forgery passes no receiver that checks receipts, and a forged record stops its generation. */
	coreContained: "core-compromise-contained",
	/** No grant issued through the token endpoint gives a token whose subject is a client. */
	noClientSubjectToken: "no-client-subject-token",
});

export type PromiseName = (typeof promiseNames)[keyof typeof promiseNames];

/**
 * Where a module stands on one promise: it holds what the promise rests on, or it breaks it, naming
 * the setting (a key path, never its value) where one does and why.
 */
export interface Stance {
	readonly promise: PromiseName;
	readonly holds: boolean;
	/** The module that stands so, as the judgment names it. */
	readonly by: string;
	readonly setting?: string;
	readonly reason?: string;
}

/** What breaks a promise: the module, the setting where there is one, and why. */
export interface Breaking {
	readonly by: string;
	readonly setting?: string;
	readonly reason?: string;
}

/**
 * One promise's judgment: held where a module stands holding it and none breaks it. Its basis is
 * `declared`: the composition and its settings were checked, the operator's conditions and the
 * receivers' duties not.
 */
export interface PromiseJudgment {
	readonly promise: PromiseName;
	readonly held: boolean;
	readonly basis: "declared";
	readonly breaking: readonly Breaking[];
}

/** Every module's stances; a contract may demand its takers contribute here (`takersContribute`). */
export const stances = extensionPoint<Stance>("promises.stances", { multiplicity: "many" });

/** The judgment of every promise, in the order `promiseNames` gives them. */
export const promises = contract<{ judgment(): readonly PromiseJudgment[] }>("promises.judgment");

/** What a first key's evidence trusts, each one word; this module owns the words. */
export const trustedNames = Object.freeze({
	/** The inbox a token is mailed to. */
	inbox: "inbox",
	/** A password the person knows. */
	password: "password",
	/** A device the person holds: a security key, an authenticator app. */
	device: "device",
	/** The IdP the person is moved from. */
	formerIdp: "former-idp",
});

export type Trusted = (typeof trustedNames)[keyof typeof trustedNames];

/** Guesses a party without the secret gets: at most `count` in any window of `windowMs`, on each instance, as each counts its own. */
export interface Guesses {
	readonly count: number;
	readonly windowMs: number;
}

/**
 * How hard a kind of evidence is to pass without what it trusts, in this module's words, so one who
 * relies on the tokens can tell the weakest kind composed by its values. A kind declared is not said
 * to be asked of every key: one asked only of those who hold it binds no key of one who does not.
 */
export type Strength =
	/** A secret the person knows, its guesses bounded (a password). */
	| { readonly kind: "guesses"; readonly guesses: Guesses }
	/** A random secret sent apart, used once (an email's token): its bits and how long it lives. */
	| { readonly kind: "secret"; readonly bits: number; readonly lifetimeMs: number }
	/** A one-time code: its digits, the windows taken on either side, and its guesses (TOTP). */
	| {
			readonly kind: "code";
			readonly digits: number;
			readonly windows: number;
			readonly guesses: Guesses;
	  }
	/** A key the person holds, signing a challenge (a security key): whether it verifies its user. */
	| { readonly kind: "key"; readonly userVerified: boolean }
	/** A login at an IdP the person is moved from: its issuer, and the authentication asked of it (acr), if any. */
	| { readonly kind: "issuer"; readonly issuer: string; readonly acr?: readonly string[] };

/**
 * One kind of evidence a first key may be bound by, as the module that checks it declares it: what
 * it trusts, and how strong it is. It is told apart from the judgment: no promise holds or breaks by
 * it.
 */
export interface EvidenceKind {
	/** The kind's name, one for each kind, the module's own and kept stable: those who rely on tokens key by it, as `first-key` composes by it. */
	readonly kind: string;
	/** The module that declares it: the one that checks it, or one that declares a kind no longer composed. */
	readonly by: string;
	readonly trusts: readonly Trusted[];
	/**
	 * Under the same name where it changed, the name being the kind's: the weaker, as the deployment
	 * declares it in its module's settings while keys bound under it live, and lifts when it judges.
	 */
	readonly strength: Strength;
	/**
	 * A kind no longer composed, declared while keys it bound live on: the weakest kind is the
	 * weakest any living key was bound by, not the weakest composed now. Only for such a kind.
	 */
	readonly past?: true;
	/**
	 * A key may have been bound by this kind alone, no other kind beside it: one meaning, whatever
	 * kind carries it. Any kind may.
	 */
	readonly alone?: true;
}

/** Every kind of a first key's evidence declared, one by its name. */
export const evidenceKinds = extensionPoint<EvidenceKind>("promises.evidence-kinds", {
	multiplicity: "keyed",
	keyOf: (kind) => kind.kind,
});

/** The kinds of a first key's evidence declared, by name: what each trusts and how strong it is. */
export const evidence = contract<{ kinds(): readonly EvidenceKind[] }>("promises.evidence");
