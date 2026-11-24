import { z } from "zod";

/** The amr sets that meet an acr, non-empty sets in a non-empty list: a session holding all of any one set meets it. */
const amrSets = z.array(z.array(z.string()).min(1)).min(1);

export const section = z.strictObject({
	values: z
		.record(z.string(), amrSets)
		.prefault({})
		.describe("Each acr and the amr sets that meet it: one set wholly held is enough."),
});
