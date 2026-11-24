/**
 * The login screen's SDK: what the screen runs between the person and the Core, following the
 * screen–Core protocol (`sdk-core-wire`) and the log's receipts (`transparency-wire`). Shipped code
 * runs in a browser, on WebCrypto alone.
 */
export {
	type AuthorizationError,
	authorization,
	type FinishError,
	type ReadT,
} from "./authorization.ts";
export { challengeOf } from "./challenge.ts";
export type { CompletionError, CompletionOptions } from "./completion.ts";
export {
	type FirstKeyOptions,
	firstKey,
	type Mail,
	type ReadCreation,
	type ReadPossession,
} from "./first-key.ts";
export type { Sealed } from "./hpke.ts";
export type { Jwk } from "./jws.ts";
export { type ScreenKeys, screenKeys } from "./keys.ts";
export { management, type ReadManage } from "./management.ts";
export {
	type Purpose,
	readStatement,
	type StatementError,
	type StatementOptions,
} from "./statement.ts";
