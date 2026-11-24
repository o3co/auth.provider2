import { z } from "zod";

/** How the list of closings is spread; the card says why the defaults. */
export const section = z.strictObject({
	"closing-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.prefault(1024)
		.describe("How many shards the list of sessions still closing is spread over."),
	"closings-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe("How many sessions still closing one shard holds at most."),
});
