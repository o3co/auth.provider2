import { auditEvents } from "@mod/audit";

/** What token introspection records. */
export default auditEvents({
	"introspection.unavailable": {
		attributes: ["source"],
		when: "introspection is answered unavailable",
	},
});
