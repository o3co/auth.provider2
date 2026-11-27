import { createHash } from "node:crypto";
import { ownerLabel } from "../orphans/orphans.ts";

/** The name the suite's server reaches this machine by, and the IPv4 address it is given where Docker gives it none. */
export interface ComposedHost {
	readonly name: string;
	readonly mapped?: string;
}

/** The suite's images, as its compose file names them: its own at the pinned tag, the store's as the pinned file's default. */
const imageOf = (tag: string) => ({
	mongodb: "mongo:6.0.13",
	nginx: `registry.gitlab.com/openid/conformance-suite/nginx:${tag}`,
	server: `registry.gitlab.com/openid/conformance-suite:${tag}`,
});

/** What the compose file beside the suite's own sets: the pinned tag, the suite's public origins, the certificate's files, the process that owns it. */
export interface Composed {
	readonly tag: string;
	readonly origins: { readonly base: string; readonly mtls: string };
	readonly tls: { readonly cert: string; readonly key: string };
	readonly owner?: number;
}

/** A path as a YAML string Compose reads as written: quoted, and its `$` doubled so nothing is interpolated. */
const yamlPath = (path: string) => JSON.stringify(path.replaceAll("$", "$$$$"));

/**
 * The compose file beside the suite's own: its images at the pinned tag, its public origins and its
 * server's profile (`dev`, whose API answers without a login), written here, so nothing in the
 * runner's environment sets them (vitest sets `BASE_URL` to `/` for Vite, which the suite's compose
 * file would take for its origin); its store in memory, never a
 * directory of this machine's (a run's store is thrown away, and Docker Desktop's shared directories
 * can refuse its writes); its server reaching this machine by name, mapped to an IPv4 address alone
 * (`host-gateway` adds an IPv6 one the suite's Java may pick and find no route to); every container
 * labelled with the process that owns it; its nginx answering with the harness's certificate, which
 * names the suite's host, so a client checking names can reach it.
 */
export const composeOverride = (host: ComposedHost, composed: Composed) => {
	const labels = `    labels:\n      ${ownerLabel}: "${composed.owner ?? process.pid}"\n`;
	const image = imageOf(composed.tag);
	return `services:
  mongodb:
    image: ${image.mongodb}
    volumes:
      - type: tmpfs
        target: /data/db
${labels}  nginx:
    image: ${image.nginx}
    volumes:
      - type: bind
        source: ${yamlPath(composed.tls.cert)}
        target: /etc/ssl/certs/nginx-selfsigned.crt
        read_only: true
      - type: bind
        source: ${yamlPath(composed.tls.key)}
        target: /etc/ssl/private/nginx-selfsigned.key
        read_only: true
${labels}  server:
    image: ${image.server}
    environment:
      BASE_URL: ${composed.origins.base}
      BASE_MTLS_URL: ${composed.origins.mtls}
      SPRING_PROFILES_ACTIVE: dev
${host.mapped === undefined ? "" : `    extra_hosts:\n      - "${host.name}:${host.mapped}"\n`}${labels}`;
};

/** A start's Compose project: one of its own, from its whole directory, as every start's ends alike. */
export const projectOf = (dir: string) =>
	`o3co-oidf-${createHash("sha256").update(dir).digest("hex").slice(0, 16)}`;
