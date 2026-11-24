import { promiseNames, type Stance } from "@mod/promises";

/** Where the token endpoint stands, as issuing access tokens asks of its taker: each bundle is recorded before any of it is signed. */
export const tokenEndpointStance: Stance = Object.freeze({
	promise: promiseNames.coreContained,
	holds: true,
	by: "token-endpoint",
});
