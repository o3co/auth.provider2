# gauge

Internal module of `metrics`: a gauge, read only when sampled, within a bound.

## Responsibilities
- Reads a gauge at each sample within the bound `metrics` gives, and answers its series, or none and why.

## Not here
- What a gauge reads: its emitter's. The bound itself, and the counters' and histograms' records: `metrics`.

## Offers
- `sampledGauge` (the gauge, the log, the bound in ms) → `record` (nothing to record), `read` (no series) and `sample` (the series read now).

## Invariants
- A gauge's read that throws, fails, is late, or gives a series undeclared, not finite or given twice leaves that gauge with no series.
- Each such read warns with the name and why, never the error, and the sample still answers.

## Depends on
- None (`metrics`' contract, instruments and registry)
