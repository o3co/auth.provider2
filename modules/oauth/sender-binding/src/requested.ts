import type { Requested, RequestedBy, SenderBinding } from "./contract.ts";

/** The binding an authorization request asks for ahead, read by each kind that names a parameter. */
export function requestedReader(kinds: readonly SenderBinding[]) {
	const asking = kinds.flatMap((kind) => (kind.requested ? [{ kind, by: kind.requested }] : []));
	const readOne = (kind: SenderBinding, by: RequestedBy, value: string): Requested => {
		const confirmation = by.confirmationOf(value);
		if (confirmation === undefined) return { kind: "malformed", parameter: by.parameter };
		const binding = { member: kind.member, confirmation, tokenType: kind.tokenType };
		return { kind: "requested", binding };
	};
	return (param: (name: string) => string | undefined): Requested => {
		const asked = asking.flatMap(({ kind, by }) => {
			const value = param(by.parameter);
			return value === undefined ? [] : [readOne(kind, by, value)];
		});
		if (asked.length > 1) return { kind: "multiple_bindings" };
		return asked[0] ?? { kind: "none" };
	};
}
