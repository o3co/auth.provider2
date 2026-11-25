import { logTyps, type Receipt, schemas } from "@mod/transparency-wire";
import { digest } from "./bytes.ts";
import { type Jwk, verifyCompact } from "./jws.ts";

/** What an approval's receipt must bind: T's compact bytes, the assertion's bytes and the code. */
export interface ApprovalBound {
	readonly statement: string;
	readonly assertion: Uint8Array;
	readonly code: string;
}

/** A receipt signed by one of the log's keys, of the receipt's `typ` and schema; none otherwise. What it binds is its reader's. */
export async function readLogReceipt(
	jws: string,
	log: readonly Jwk[],
): Promise<Receipt | undefined> {
	const verified = await verifyCompact(jws, log);
	if (!verified || verified.header.typ !== logTyps.receipt) return undefined;
	const read = schemas.receipt.safeParse(verified.payload);
	return read.success ? read.data : undefined;
}

/**
 * The receipt of an approval's record (⑤, A35): signed by one of the log's keys, of the receipt's
 * `typ` and schema, an `approval` record's, binding the digests of T, the assertion and the code.
 */
export async function readApprovalReceipt(
	jws: string,
	log: readonly Jwk[],
	bound: ApprovalBound,
): Promise<Receipt | undefined> {
	const receipt = await readLogReceipt(jws, log);
	const approval = receipt?.kind === "approval" ? receipt.approval : undefined;
	if (!receipt || !approval) return undefined;
	const binds =
		approval.statement === (await digest(bound.statement)) &&
		approval.assertion === (await digest(bound.assertion)) &&
		approval.code === (await digest(bound.code));
	return binds ? receipt : undefined;
}
