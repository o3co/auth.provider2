import type { UsersHttpSettings } from "./module.ts";

export type { UsersHttpSettings };

/** A credential for tests: 32 bytes of key material as base64url, of many byte values. */
export const testCredential = "1u5WlyPfoo3WbtzhCkOK_wO2lL4DQKc4MWJFPS8L6_Q";

/** The section of a test's configuration: the test credential, and the password call's and lookups' URLs at one origin under `.invalid`. */
export function usersHttpConfig(settings: Partial<UsersHttpSettings> = {}) {
	return {
		"users-http": {
			"verify-url": "https://ledger.example.invalid/verify",
			"subject-url": "https://ledger.example.invalid/subject",
			"identifier-url": "https://ledger.example.invalid/identifier",
			credential: testCredential,
			...settings,
		} satisfies UsersHttpSettings,
	};
}
