import { auditEvents } from "@mod/audit";

/** What refresh records; never a token or its secret. */
export default auditEvents({
	"refresh.key_bound": {
		attributes: ["client", "binding", "thumbprint"],
		when: "a code's redemption founds no family, its key bound to another family (Q27): the binding's kind and the key's thumbprint",
	},
});
