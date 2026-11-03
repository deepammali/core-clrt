# 005: Docker Failure Fallback and Environment Switches

## Status

Accepted.

## Context

Docker Desktop is available on this machine, but image builds can still fail
because of registry, package repository, or port conflicts.

## Decision

If the Docker range cannot be built or started, write a detailed command file
to:

`/var/folders/qy/ktffbxx54kd7509tlpr42l040000gn/T/opencode/CART_REAL_RANGE_SETUP.md`

The file must include:

- `docker build -t cart/host-a:cve-2021-41773 docker/host_a`
- `docker build -t cart/host-bc:alpine docker/host_bc`
- `docker network create --driver bridge cart-core-range`
- exact `docker run` commands for `cart-core-host-a` and `cart-core-host-bc`
- the port bindings `127.0.0.1:18080:80`,
  `127.0.0.1:12222:22`, and `127.0.0.1:15432:5432`
- the PostgreSQL environment variables
  `POSTGRES_USER=app`, `POSTGRES_PASSWORD=AppP@ssw0rd`,
  `POSTGRES_DB=appdb`
- the manual verification commands for the Apache traversal, SSH login, and
  PostgreSQL flag query
- `python3 -m unittest -v test_executor.py`

Environment switches:

- `CART_SKIP_REAL=1` skips real parity tests while keeping emulated tests.
- `CART_KEEP_RANGE=1` keeps containers and the network after tests.
- `CART_REBUILD_IMAGES=1` forces image rebuilds.
- `CART_HOST_A_PORT`, `CART_HOST_BC_SSH_PORT`, and `CART_HOST_BC_PG_PORT`
  override the published ports.

## Consequences

- Emulated tests still run if Docker is unavailable.
- Real tests skip with a clear reason rather than silently faking success.
- A reviewer can reproduce the exact real range from the generated command
  file.
