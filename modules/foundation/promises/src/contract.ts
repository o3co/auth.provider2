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
