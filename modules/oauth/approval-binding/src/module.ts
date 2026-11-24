import { statementItems } from "@mod/approvals";
import { defineModule } from "@mod/kernel";

// Declares one item and holds nothing.
export default defineModule({ name: "approval-binding", replicaSafe: true, takes: [] }, (m) => [
	// The key the RP's tokens will be bound to, as its JAR names it ahead (RFC 9449 §10): the authorization's `dpop_jkt`.
	m.contribute(statementItems).by(() => ({
		purpose: "authorization",
		names: ["dpop_jkt"],
		by: "approval-binding",
	})),
]);
