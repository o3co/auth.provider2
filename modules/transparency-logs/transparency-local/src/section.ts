import { setting } from "@mod/kernel";
import { z } from "zod";

const duration = (unit: "s" | "ms", at: string, what: string) =>
	setting.duration(unit).pipe(z.number().int().min(1)).prefault(at).describe(what);

export const section = z.strictObject({
	origin: z
		.string()
		.min(1)
		.describe(
			"The origin a passkey's assertion is judged for: the login screen's, one of `webauthn.origins`.",
		),
	"code-lifetime": duration(
		"ms",
		"10m",
		"How long after its approval a code's start is on time: no shorter than the code's own lifetime.",
	),
	"refresh-lifetime": duration(
		"ms",
		"365d",
		"How long after its family was made a refresh's start is on time: no shorter than a family's own lifetime.",
	),
	"issue-window": duration(
		"ms",
		"1m",
		"How long after its start a bundle is on time: longer than a Core request's deadline.",
	),
	"evidence-window": setting
		.duration("ms")
		.pipe(z.number().int().min(360_000))
		.prefault("10m")
		.describe(
			"How far a client's evidence's times may lie from its start's acceptance: at least 6m, longer than client-assertion's clock-skew and dpop's proof-window (5m at most each) by a Core request's deadline.",
		),
});

export type Settings = z.output<typeof section>;
