# compose

Internal module of `interop-oidf`: how the suite's containers are composed beside the suite's own compose file.

## Responsibilities
- Writes the compose file beside the suite's own, which sets everything a run depends on itself, and names a start's Compose project.

## Not here
- Running Compose: `suite`.

## Offers
- `composeOverride` (the name the server reaches this machine by, and `Composed`: the pinned tag, the suite's origins, the certificate's files, the owner): the images at the tag (the store's as the pinned file's default), the origins and the server's profile, the store in memory, the harness's certificate for nginx, each container labelled with its owner.
- `projectOf`: a start's Compose project, from a hash of its whole directory.

## Invariants
- What the suite's own file reads from the environment and a run depends on (the images, the origins, the server's profile `dev`, whose API answers without a login) is written in the file, never taken from the runner's environment: vitest sets `BASE_URL` to `/` for Vite, which the suite's own file would take for its origin. The certificate's paths are quoted, nothing in them interpolated.
- The store is never a directory of this machine: a run's store is thrown away, and Docker Desktop's shared directories can refuse its writes.
- The server's name for this machine maps to IPv4 alone: `host-gateway` adds an IPv6 address the suite's Java may pick and find no route to.

## Depends on
- `orphans` (its label).
