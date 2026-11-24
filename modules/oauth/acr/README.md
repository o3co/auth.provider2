# acr

## Responsibilities
- Holds the operator's acr table, and the ways of logging in a composition declares, each by the amr it can prove.
- Answers, for the acr a request asks for, which ones the table knows and which one a session's amr meet.
- Checks at boot that the declared ways of logging in can meet every acr in the table.
- Names the offered acr among `issuer`'s metadata items.

## Not here
- The authorization endpoint's decisions, the login facts (amr and the time of authentication) a login gives, and the amr the approval's way of logging in declares: `authorize`.
- What each amr value means: the declaring side's.
- The kinds of evidence a first key was bound by (a password, an existing MFA, a former IdP): never declared here, as no login proves them; a login's amr names its approval alone.

## Offers
- `acr`: the known acr among the request's `acr_values`, in the order asked; the first of them a session's amr meet; and the session's current acr, the first in the table's order its amr meet.
- Extension point `amrSources`: the amr a way of logging in can prove, under its name, keyed by name; the names are its own words, never read here.
- Contribution to `issuer`'s metadata: `acr_values_supported`, the operator's table in its order; left out when empty.
- Operator section: `values`, each acr and the amr sets that meet it, each set and each list non-empty; default empty.
- `./testing`: `acrConfig`, a test configuration builder.

## Invariants
- An acr is met when a session holds every amr of any one of its sets.
- The first acr asked that is met wins; acr have no order of strength.
- An acr is known only by its exact name as an own entry of the table.
- The table's order is the operator's written order, but a name that reads as an integer (`0`, `1`, `2`) comes first, ascending, as the configuration is read as an object. A table of two entries or more holding one warns at every start, `acr.values_order` with those names: written as a name that does not read as an integer (`loa-1`), it keeps its written order. Every acr answered is one the session meets, so the order never answers one stronger.
- Boot is refused, at `acr.values.<acr>` and never in the text, for an acr none of whose sets the declared ways of logging in can prove between them; with none declared, for every acr in the table.

## Data
- The table, read once at boot; nothing is stored.

## Depends on
- `kernel`, `issuer`

## Vocabulary
- table: for each acr, the amr sets that meet it.
- way of logging in: what proves a set of amr at a login: an approval and its continuation steps, declared by `authorize`.
