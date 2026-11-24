import { expect, it } from "vitest";
import { sessionStoreNeeds, subjectSessionsNeeds } from "../src/store.ts";

it("asks every store, the listing included, to read only what a failover keeps", () => {
	for (const needs of [sessionStoreNeeds, subjectSessionsNeeds]) {
		expect(needs).toMatchObject({ survivesFailover: true, readsConfirmed: true });
	}
});
