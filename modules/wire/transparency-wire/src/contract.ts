/**
 * The contract of the transparency log, which the log and the monitor hold and the Core's writers,
 * the receivers and their companions follow: the words, the schemas of what each side signs, sends
 * or reads, and the inputs a digest or a sealing covers. Signing, sealing and judging are each
 * side's own.
 */
import {
	checkpoint,
	judgment,
	judgments,
	setSigned,
	stateOf,
	status,
	statusReasons,
	statusWords,
} from "./judging/judging.ts";
import {
	callbackHeader,
	callbackProof,
	idTokenEvidence,
	receipt,
	tokens,
} from "./receipt-gate/receipt-gate.ts";
import {
	appendAnswer,
	appendRefusals,
	appendRequest,
	opIds,
	preimage,
	record,
	recordRef,
	sealing,
} from "./records/records.ts";
import { bodies, signedRecord, signerSet, signers } from "./signed-bodies/signed-bodies.ts";
import { flows, logTyps, recordKinds, speaks } from "./words/words.ts";

export type {
	Checkpoint,
	Judgment,
	StageOutcome,
	StateOf,
	Status,
	Verdict,
} from "./judging/judging.ts";
export type {
	CallbackCheck,
	CallbackFault,
	Receipt,
	ReceiptCheck,
	ReceiptFault,
} from "./receipt-gate/receipt-gate.ts";
export type {
	AppendAnswer,
	AppendRequest,
	Flow,
	LogRecord,
	Preimage,
	RecordRef,
	Writer,
} from "./records/records.ts";
export type { ReceiverKey, SignerSet } from "./signed-bodies/signed-bodies.ts";
export {
	appendRefusals,
	flows,
	judgments,
	logTyps,
	opIds,
	recordKinds,
	sealing,
	signers,
	speaks,
	statusWords,
	tokens,
};

/** The schemas, as each side reads what it received or verified to them. */
export const schemas = Object.freeze({
	appendRequest,
	appendAnswer,
	record,
	receipt,
	judgment,
	checkpoint,
	status,
	statusReasons,
	stateOf,
	preimage,
	recordRef,
	signerSet,
	/** The signed bodies of the records no Core writer writes, each with its `typ`. */
	bodies,
	signedRecord,
	setSigned,
	callbackHeader,
	callbackProof,
	idTokenEvidence,
});
