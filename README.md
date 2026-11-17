# Commonfield

Commonfield is a self-hosted team whiteboard: an administrator creates a workspace, invites members, and collaborates on a shared board with persistent coloured sticky notes. This repository includes the application, PostgreSQL schema, focused tests and a portable Docker installation.

## License

Copyright (C) 2026 Guillermo Moreno.

CommonField is free software licensed under the **GNU Affero General Public License,
version 3 or (at your option) any later version** (`AGPL-3.0-or-later`). See
[LICENSE](LICENSE) for the complete terms and [NOTICE](NOTICE) for the project notice.

You may use, modify and redistribute CommonField, including commercially, subject
to those terms. If you run a modified version as a network service, you must
prominently offer its users access to the corresponding source code as required
by section 13. The source must correspond to the version they are using, including
modifications, not just link to an unchanged upstream repository.

CommonField is provided without warranty. Third-party dependencies and assets
retain their own licences and copyright notices; this project licence does not
replace them.

## Local installation

Requirements: Git, Docker Engine/Desktop with the **Docker Compose v2** plugin, a POSIX shell, and internet access for the first build. No host Node.js, Python or package manager is required. On Windows use WSL2. Docker daemon access is administrative access; use a trusted host.

```sh
git clone https://github.com/spitefulme/CommonField.git commonfield
cd commonfield
./setup.sh
docker compose up -d --build --wait
```

Open **http://localhost:8080/bootstrap** and create **your own** name, email, team and password. There is no shipped administrator account. Bootstrap is transactional and available once per database. Use the same hostname as the configured origin, not an alternate IP. Sign in after creating the workspace.

The app listens on loopback only. PostgreSQL and internal SMTP have **no published ports**. The capture inbox at **http://localhost:8025** is also loopback-only. Default `EMAIL_MODE=capture` captures invitations locally; it does **not** email recipients. For real delivery, explicitly enable the [authenticated TLS SMTP override](docs/smtp.md) with private credential files and a verified provider sender. “SMTP accepted” means transport acceptance, never confirmed inbox delivery. No real provider or recipient receipt is claimed by this release.

```sh
docker compose ps
docker compose logs --tail=50 app migrate
docker compose stop                 # retain data
# docker compose down also retains named data volumes
```

For different ports, copy `.env.example` to `.env`, update **both** `APP_PORT` and `PUBLIC_ORIGIN`, then start. Example: `APP_PORT=8081`, `PUBLIC_ORIGIN=http://localhost:8081`. Origin must be exact, with no trailing slash or path.

**Keep `.commonfield/` private and backed up.** Setup generates random database credentials and a stable invitation-encryption key there; rerunning setup validates and preserves existing keys. Never commit or upload this directory. Do not regenerate it against an existing database.

## Server installation

[Server HTTPS setup](docs/installation.md) includes a Caddy override and the required **private first-owner bootstrap before public exposure**. [Operations](docs/operations.md) covers backup/restore, upgrades, keys, limitations and diagnostics. [Testing](docs/testing.md) provides repeatable smoke commands, and the [verification summary](docs/verification.md) records what was actually exercised and what remains unverified.

## Architecture and scope

One non-root combined TypeScript/React backend/frontend service, one PostgreSQL instance, one private Mailpit capture service (default), and optional outbound Nodemailer SMTP delivery. A separate short-lived migration service runs before application startup. Writer authority uses PostgreSQL advisory ownership and generation/nonce fencing; readiness includes live database access and writer ownership. **Run one application replica only.** No proprietary agent framework, external identity registry or paid runtime is required.

Dependencies are pinned in `pnpm-lock.yaml`; the Docker build verifies pnpm 12.18.0 and runs the included tests, TypeScript checks and frontend/backend compilation. Node.js 22.22.0 is used in the image. The implementation remains an early team-board release: shipping this package is not a claim of full product acceptance, production security certification or measured capacity for twenty concurrent users.
