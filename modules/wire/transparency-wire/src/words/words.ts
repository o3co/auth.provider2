/** The wire versions a reader of this protocol speaks; every object names one of them as `v`. */
export const speaks = Object.freeze([1] as const);

/** The `typ` of each signed object. */
export const logTyps = Object.freeze({
	receipt: "receipt+jwt",
	judgment: "judgment+jwt",
	checkpoint: "checkpoint+jwt",
	status: "status+jwt",
	/** The reasons of the status's not-accepted ids, for operators, apart from the status. */
	statusReasons: "status-reasons+jwt",
	stateOf: "state-of+jwt",
	keySet: "key-set+jwt",
	confirmation: "confirmation+jwt",
	denial: "denial+jwt",
	erasureBoundary: "erasure-boundary+jwt",
	resetBoundary: "reset-boundary+jwt",
	tombstone: "tombstone+jwt",
	coreRingKey: "core-ring-key+jwt",
	signerSet: "signer-set+jwt",
	/** Signed by people's keys, in an encoding not yet decided: no `+jwt`, as it may be no JWS. */
	stopInstruction: "stop-instruction",
	restartApproval: "restart-approval",
	/** An embedder's reset instruction (reset-wire's payload), which a reset boundary carries. */
	resetInstruction: "reset-instruction+jwt",
	/** The callback's proof the login screen signs with E_sig (A38). */
	callback: "callback+jwt",
});

/** The record kinds, by the writer role that may write each; a role writes no other kind. */
export const recordKinds = Object.freeze({
	core: Object.freeze([
		"approval",
		"keyChange",
		"start",
		"bundle",
		"noEffect",
		"abandonment",
	] as const),
	monitor: Object.freeze([
		"keySet",
		"confirmation",
		"denial",
		"erasureBoundary",
		"resetBoundary",
		"tombstone",
	] as const),
	publisher: Object.freeze([
		"registryVersion",
		"configVersion",
		"coreRingKey",
		"signerSet",
	] as const),
	/** The generation flow's kinds, signed by people's keys. */
	human: Object.freeze(["stopInstruction", "restartApproval"] as const),
	/** The log's empty commit. */
	log: Object.freeze(["tick"] as const),
});

/** What a flow is the flow of; an unconditional flow's append names no previous position. */
export const flows = Object.freeze({
	units: Object.freeze(["subject", "client", "publisher", "generation", "monitor"] as const),
	unconditional: Object.freeze(["client"] as const),
});

/** The frames a bundle names its tokens by, each once: the tokens' `frames`. */
export const frames = Object.freeze(["accessToken", "idToken", "family"] as const);
