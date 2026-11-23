# metrics-log

## Responsibilities
- Writes what `metrics` samples to `kernel`'s log, one line at start and one at each interval, with no route and no listener: an adapter of the metrics axis for a deployment whose counts leave by its log alone.

## Not here
- What is counted, its names and labels (the emitting modules'), and the registry, the label sets and the gauges' reads (`metrics`'). Whether a promise holds: the module judging it, through a gauge of its own, which goes in the line as any gauge does.
- Where a line goes once logged, and the level that drops it (`kernel` and its sinks).
- Publishing the counts on a route: `metrics-prometheus`, the axis's default.

## Offers
- Composition definition only: the sampling, at start and each interval. A composition names it on the metrics axis to compose it.
- Operator section `metrics-log`: `interval`, how often a line is written, from `1s` to `1h`, `60s` unless set.
- Each line is `info`, event `metrics.sample`, a field for each series `metrics` samples, its value the series' number:
  - a counter's or a gauge's: `<name>{<label>=<value>,…}`, the labels in declared order, each value as JSON writes a string, `<name>{}` for one with no labels (`up{part="a"}` for a gauge `up` labelled `part`);
  - a histogram's: that name followed by `.le=<bound>` for each bucket's cumulative count, then `.sum` and `.count`.

## Invariants
- One line is written at start, which waits for it (each gauge read within `metrics`' bound), so every boot tells at once; then one each interval, never two samples at once. An assembly never started, or stopped, writes none.
- Every gauge is read anew for each line; one whose read fails or is late has no field, and the line is still written.
- A field never takes a line's own name (`level`, `event`, `at`), and no label value is read as another label or series: each name holds braces and its values are JSON strings.
- A line holds only the series `metrics` gives, so no request's path or query reaches it.
- Each instance writes only its own counts, so the module is safe on multiple instances.

## Depends on
- `kernel`, `metrics`, `zod`

## Vocabulary
- sample line: one log line holding every series of one `metrics.sample()`.
