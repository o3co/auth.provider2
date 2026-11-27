# {{title}}

{{use}}

{{card}}

## Start

`pnpm install`, then the setup below, then `pnpm start`. The app reads the configuration files `APP_CONFIG` lists, comma-separated (default `config/application.conf`); put `config/local.conf` first to layer it: `APP_CONFIG=config/local.conf,config/application.conf`.

The scripts:

{{scripts}}

## Setup the composed packages ask for

{{chosen}}

## Values you decide

{{decides}}

## Promises this app requires

Boot is refused where one of these does not hold (`promises.required` in `config/application.conf`):

{{required}}

## Configuration

Each key of `config/application.conf` reads its environment variable, set in `.env` (see `.env.example`):

| Key | Variable |
|---|---|
{{settings}}

Written in the local layer (`config/local.conf`, see `config/local.conf.example`): lists, and values of several lines.

{{written}}

## Permissions

`pnpm start` runs `src/start.ts`, which starts the app's entry under Node's permission model, as `APP_PERMISSION` says: `audit` (the default) runs it with every grant `permissions.json` and the configuration give, writing each permission event as a JSON line (`"event":"app-permissions.event"`) on standard error; `enforce` refuses what is not granted; `off` holds nothing. Under `audit` no line should come: one that does names a read, a process or a connection no package declares. `pnpm start --print` writes the command it would run, for this configuration, without running it. On Windows the entry starts only with `APP_PERMISSION=off`. Keep secrets outside the app's directory and the package trees, and outside what their links reach: those are read.

## Network

`network.json` lists, for each process the app runs, the network words its packages declare, and the package declaring each. It is the input to enforcement, not enforcement.

## Packages

Each package's card, as installed, is the truth about it:

{{cards}}
