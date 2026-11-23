import type { Reading } from "@mod/metrics";

/**
 * A series' field name: the instrument's name, then its labels in declared order, each value as JSON
 * writes a string, in braces, so no value is read as another label and no name is a line's own.
 */
const seriesName = (reading: Reading, labels: Readonly<Record<string, string>>) =>
	`${reading.name}{${reading.labels.map((label) => `${label}=${JSON.stringify(labels[label])}`).join(",")}}`;

/**
 * The fields of one sample line: a counter's or gauge's series by its name, a histogram's as its
 * name with `.le=<bound>` for each bucket's cumulative count, `.sum` and `.count`.
 */
export function fieldsOf(readings: readonly Reading[]): Record<string, number> {
	return Object.fromEntries(
		readings.flatMap((reading): (readonly [string, number])[] =>
			reading.kind === "histogram"
				? reading.series.flatMap((series) => {
						const named = seriesName(reading, series.labels);
						return [
							// One cumulative count per bucket's bound; the last, for all, is `count`.
							...reading.buckets.map(
								(bound, i) => [`${named}.le=${bound}`, series.counts[i] ?? 0] as const,
							),
							[`${named}.sum`, series.sum] as const,
							[`${named}.count`, series.count] as const,
						];
					})
				: reading.series.map(
						(series) => [seriesName(reading, series.labels), series.value] as const,
					),
		),
	);
}
