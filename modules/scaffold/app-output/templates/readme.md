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

## Network

`network.json` lists, for each process the app runs, the network words its packages declare, and the package declaring each. It is the input to enforcement, not enforcement.

## Packages

Each package's card, as installed, is the truth about it:

{{cards}}
