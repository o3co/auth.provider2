# lifecycle

Internal module of `interop-oidf`: what every plan run has, its directories and its stops.

## Responsibilities
- Makes a plan's directories and runs its stops, so every run ends the same way however it went.

## Not here
- How long a plan may take: the plan's run, from the plan's own timing.

## Offers
- `planDirs`: a plan's work directory, one of its own, and its records directory, under the one named (`artifactsOf`) or one of its own.
- `keptThenStopped`: a stop that keeps its records first; `stopAll`: every stop, the last pushed first, each failure answered; `cleared`: the work directory removed where everything stopped.

## Invariants
- Every stop is tried, though one before it failed; none is swallowed.
- A stop that failed, a suite's start that could not stop the suite included, keeps the work directory: it holds what stops that part, for the next run to take down.
- Each plan's records are in a directory of its own, so plans never mix theirs.

## Depends on
- `suite` (`SuiteStopFailed`).
