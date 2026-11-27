# entries

Internal module of `app-entries`: the scripts a generated app's composed packages declare, each written by its shape.

## Responsibilities
- Reads each composed package's `appEntries`, refusing what cannot be taken, and writes each entry's script and file by its shape.

## Not here
- The app's entry and start, and what every entry shares (its refusal, the packages it imports): the package's `start` and `launcher`.

## Offers
- `entriesOf` (the composed modules, what each is imported as, the command that runs a file, where keys are written, what the composed packages declare) → each entry's script and file; `Declaring`, `Shape`.

## Invariants
- A composed package declares its entries in its manifest's `appEntries`, each `{ script, shape, contract, member }`: the contract an export of its main entry, and the member of it the shape calls. One that cannot be read, a key its shape does not take, or a script two declare, is refused, naming the package. The shapes:
  - `call`: the member, given the arguments unread, answers `{ lines, code }`. The arguments never carry a subject. The lines are the member's own, written to standard output once it answers (a run that is killed writes none); it exits with the code, 0 to 77, and 78 on a refused boot, which no member may answer. Any other answer, or a throw, is a fixed line and 1: not finished, look and run again.
  - `settle-subjects`: takes `answers` too, the answers counted in the order its line tells them, each a lowercase word, none twice, and neither `unknown` nor `failed`.
    - It settles each subject read from standard input, one a line, empty lines skipped, each other line used as sent, through the member, and writes only how many gave each answer, then unknown (an answer it does not know) and failed (unavailable), never a subject.
    - It exits 0 where none failed and none was unknown, else 1, and 78 on a refused boot, told by the kernel's mark as the app's is.
  - `settle-records`: takes `answers` as `settle-subjects` does, and settles each record read from standard input, one JSON object a line, empty lines skipped, handing the member the object as read; a line that is no JSON object is counted failed. It writes and exits as `settle-subjects` does, never a record.
  - `name-subjects`: reading subjects as `settle-subjects` does, it writes each subject the member answers above 0 for, one a line on standard output, as the operator gave it, and the counts (named, clear, failed) on standard error. It exits 0 where none failed, else 1, and 78 on a refused boot.
  - `answer-lines` (`longest`, 1 to 65536 bytes): no argument (64). Each line of standard input, strict UTF-8, goes to the member; one line out for each, in order, as answered: the answer as JSON data, or `unread` (empty, too long, not UTF-8), `failed` (unavailable; reads on) or `stopped` (another failure, or no data; reads no further). A member answers plain JSON data. 0 where every line was answered, else 1, also where standard output closes.
- A script reading subjects writes on standard error only fixed lines beside its counts: how many refusals refused its boot, where they can be counted (exit 78), that its boot failed or that the run stopped on an unexpected error (exit 1), and that 0.17's variables are set, naming none. Never a subject, a configured value or an error's words; the app's own start tells why.
- A script reading subjects holds the process's streams (`write` and `end`), the console, warnings and errors no one catches to those lines, reading the app and its modules only after. Code writing to a descriptor itself (`fs.writeSync(1, …)` or `(2, …)`) is code the process trusts, outside it.
- In a script reading subjects, a failure other than unavailable is counted and stops the run there: the subjects after it are not read.
- Each entry checks the variables 0.17 read as the app's entry does, by `legacyVariablesCheck`, its refusal refusing the entry's boot: a `call` writes the warning as `warn config-files:`, a script reading subjects the fixed line above, naming none.
- Every declared entry, whatever its shape, assembles the app never to start (the kernel's `neverStarted`): it builds and stops, and serves nothing. The app's entry starts.
- What an entry writes is handed on before it exits: a slow pipe holds the script, never drops a line.
- The entries that read subjects read them one way: a line longer than a subject may be (255 bytes) is counted failed, and no more of it is held. `settle-records` reads its lines so, a record's longest 4096 bytes, and is a script reading subjects in every rule above, its records in their place.

## Depends on
- The package's `start` (`filled`, `refusedPart`, the packages every app depends on) and its templates.
