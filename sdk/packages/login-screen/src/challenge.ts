import { challengeInput } from "@mod/sdk-core-wire";
import { sha256 } from "./bytes.ts";

/** A WebAuthn challenge: the SHA-256 of the use and the statement's compact bytes. */
export const challengeOf = (statement: string, use: "get" | "create") =>
	sha256(challengeInput(statement, use));
