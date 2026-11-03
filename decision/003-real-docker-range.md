# 003: Two-Container Real Docker Range

## Status

Accepted.

## Context

The real mode needs proof on real sockets without turning the benchmark into a
full enterprise lab. The requirement is two lightweight containers on a local
bridge network.

## Decision

Use exactly two containers on the Docker bridge network `cart-core-range`.

Container `cart-core-host-a`:

- Image `cart/host-a:cve-2021-41773`, built from `docker/host_a`.
- Base image `httpd:2.4.49`.
- Keeps CGI execution disabled and grants directory access so the real
  `CVE-2021-41773` path traversal is served as a static file disclosure.
  Enabling `mod_cgid` makes Apache try to execute `/etc/passwd` and return
  HTTP 500, so this image deliberately leaves `cgid` commented out.
- Serves `/var/www/backup/pci_prod.conf` and `/var/www/backup/app.env` as
  leaked files.
- Published only on `127.0.0.1:18080`.

Container `cart-core-host-bc`:

- Image `cart/host-bc:alpine`, built from `docker/host_bc`.
- Base image `postgres:15-alpine`.
- Adds OpenSSH and the `cart-app` user.
- Seeds PostgreSQL user `app`, password `AppP@ssw0rd`, database `appdb`.
- Seeds `secrets(name, value)` with
  `db_admin_flag = db_admin_flag{cart_r0e_verified_2026}`.
- Serves SSH on `127.0.0.1:12222` and PostgreSQL on `127.0.0.1:15432`.
- Represents both Host B and Host C because the requirement allows two
  containers for A and B/C.

Probes:

- Host A exploit: HTTP GET
  `/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`, success only when HTTP 200 and
  `root:x:0:0` appear.
- Host A leaked config: HTTP GET
  `/cgi-bin/.%2e/.%2e/.%2e/.%2e/var/www/backup/pci_prod.conf`, success only
  when `10.10.99.50` appears.
- Host B exploit: `docker exec` SSH login as `cart-app` with the baked
  ed25519 key, success only when `id` returns `cart-app`.
- Host B post-exploitation: SSH `cat /home/cart-app/credentials.txt`, success
  only when `APP_DB_PASSWORD` appears.
- Host C objective: `psql` query for `db_admin_flag`, success only when the
  exact flag appears.

Safety:

- Probes use a 10 second timeout.
- Ports bind to `127.0.0.1`, not all interfaces.
- `10.10.99.0/24` is denied before Docker is invoked.
- Container names and network name are fixed for reproducibility.

## Consequences

- Real mode proves a genuine Apache traversal, genuine SSH login, and genuine
  PostgreSQL query.
- The range starts in under two minutes after images are built.
- The real range is never used for the 90+ trial ablations.
