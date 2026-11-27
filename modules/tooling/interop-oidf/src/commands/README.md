# commands

Internal module of `interop-oidf`: a program other than docker a plan runs (git, Python and its packages), held to its time.

## Responsibilities
- Runs a program for a plan, ended (`SIGKILL`) past its own time or where the plan's deadline aborts, and answers what it wrote to each stream apart.

## Not here
- Docker: `docker-client`'s `docker`, which every docker command of the package goes through.

## Offers
- `Command`, and `systemCommand`: the system's program, its `stdout` and its `stderr` answered apart.

## Invariants
- Every program has a time of its own, and the plan's deadline where it is given one: past either it is ended and the call fails.
- A program's `stdout` alone is what a caller parses; its `stderr` is its diagnostics.

## Depends on
- node's `child_process` (`execFile`).
