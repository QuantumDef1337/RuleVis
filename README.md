# RuleVis — Multi-Tenant Rule Intelligence Platform for Wazuh

RuleVis turns your Wazuh ruleset into a dynamic, interactive dependency graph — and wraps it in a full multi-tenant platform: RBAC, MFA, audit logging, live Wazuh/GitHub sync, webhooks, a public API, and OIDC single sign-on. It helps security teams visualize rule relationships, catch structural issues, track MITRE ATT&CK and compliance coverage, and manage rule changes with a real audit trail — across as many isolated tenant workspaces as you need.

Built for SOC analysts (understand what a rule actually does and why), SOC managers (health/coverage reporting, change auditing), and platform engineers (multi-tenant administration, integrations).

![Home dashboard](assets/dashboard.png)

## Features

### Rule intelligence
* **Interactive graph visualization** — force, hierarchical, and radial layouts, rendered on Canvas for performance at scale.
* **Rule detail panel** — a plain-English breakdown of any rule: severity, parent rules, sub-rules, and every condition that has to match for the alert to fire, laid out top to bottom.
* **Dependency analysis** — parent/child relationships (`if_sid`, `if_group`, `if_matched_sid`, `if_matched_group`) as directed edges, with broken-dependency and duplicate-ID detection.
* **Rule health dashboard** — disabled parent rules, orphan rules, MITRE ATT&CK coverage, compliance-tag coverage, dependency-chain depth.
* **Rule ID heatmap** — see which ID ranges are heavily used and which are free for new custom rules.
* **Compare** — diff two rule sets or manager snapshots.
* **Product mapping** — organize rule files into logical products (e.g. "Windows," "FortiGate") with per-product rule counts.

![Rule Visualizer](assets/visualizer.png)

### Multi-tenancy & access control
* **Isolated tenant workspaces** — each with its own rules, products, managers, GitHub sources, webhooks, and members.
* **RBAC** — `tenant_admin` / `analyst` / `viewer` roles, plus per-user permission overrides for one-off exceptions, plus a platform-wide super-admin layer.
* **Direct or invite-based user creation** — username, optional email, password, role, permission overrides, force-password-reset, and require-MFA-enrollment, all from one form.

![Team & access](assets/settings-team.png)

### Security
* **TOTP-based MFA** with QR enrollment and single-use backup codes.
* **Account lockout** and **per-IP login rate limiting** (the latter backed by the database, not an in-process counter — it holds up under multiple worker processes or hosts).
* **Secrets encrypted at rest** — Wazuh manager passwords and GitHub tokens are Fernet-encrypted before they ever touch disk.
* **Audit log & deletion log** — every administrative action, with actor, IP address, and (for rule syncs) a full added/removed/changed diff.
* **Login activity monitoring** with suspicious-activity flagging.
* **OIDC single sign-on** — works with Okta, Azure AD/Entra ID, Google Workspace, Auth0, Keycloak, or any standard OIDC identity provider.

### Integrations
* **Live Wazuh manager sync** — connect a manager's REST API, sync on demand or automatically on an interval, with full change diffing on every sync.
* **GitHub source sync** — pull rule files directly from a repository, public or private.
* **Webhooks** — push rule-change and deletion events to Slack, Microsoft Teams, or any JSON endpoint (ServiceNow, Jira, n8n, custom), HMAC-signed.
* **Public API** — scoped, revocable API keys for programmatic access, one tenant and one role per key.

![Workspace settings](assets/settings-workspace.png)

## Installation

```shell
git clone https://github.com/QuantumDef1337/RuleVis.git
cd RuleVis
pip install .
```

All dependencies (Flask, networkx, waitress, SQLAlchemy, cryptography, python-jose) install automatically via `pyproject.toml` — no manual dependency wrangling, on Windows, Linux, or macOS. The frontend ships pre-built (`src/internal/static/dist/`), so **no Node.js is required** just to run the app.

Only needed if you point RuleVis at Postgres instead of the default SQLite (see below):

```shell
pip install .[postgres]
```

## Usage

```shell
rulevis
```

This starts the server, opens your default browser to `http://localhost:5000/`, and walks you through creating the first administrator account. From there, everything — connecting rule sources, creating tenants, inviting users — happens in the app.

You can optionally seed the first tenant from local rule directories at startup:

```shell
rulevis --path /var/ossec/ruleset/rules,/var/ossec/etc/rules
```

![Login](assets/login.png)

## Database

By default RuleVis uses a local SQLite file at `~/.rulevis/rulevis.db` — zero configuration, works out of the box. For a multi-process or multi-host deployment, point it at Postgres instead:

```shell
export RULEVIS_DATABASE_URL="postgresql+psycopg2://user:pass@host/rulevis"
```

Every query in the identity/authz layer is written to be portable across both backends.

## Rebuilding the frontend

Only needed if you're changing `web/src` — running RuleVis itself does not require this.

```shell
cd web
npm install
npm run build     # outputs to ../src/internal/static/dist/
```

## Data locations

All application data lives under `~/.rulevis/`:

| Path | Contents |
|---|---|
| `rulevis.db` | Identity/authz — users, tenants, roles, audit log (or your external DB, if configured) |
| `secret_key` | Session-signing key, generated once on first run |
| `tenants/<id>/config.json` | Per-tenant products, managers, GitHub sources, webhooks, SSO config |
| `tenants/<id>/cache/<manager_id>/` | Rule files mirrored from a connected Wazuh manager |
| `tenants/<id>/cache/gh-<source_id>/` | Rule files mirrored from a GitHub source |
| `tenants/<id>/uploads/` | Manually uploaded rule XML |

## Logging

RuleVis writes diagnostic logs to a user-specific location, following OS conventions:

| Platform | Log file location |
|---|---|
| Windows | `%LocalAppData%\rulevis\Logs\rulevis.log` |
| macOS | `~/Library/Logs/rulevis/rulevis.log` |
| Linux / BSD | `$XDG_STATE_HOME/rulevis/rulevis.log` (fallback `~/.local/share/rulevis/logs/rulevis.log`) |

Safe to delete — a new one is created automatically on the next run.

## Testing

```shell
pip install .[dev]
pytest tests/
```

Every test runs against an isolated, throwaway database (redirects `HOME`/`USERPROFILE` to a temp directory per test) — nothing touches real data.

## Architecture

- **Backend**: Flask, served via [waitress](https://github.com/Pylons/waitress) in production.
- **Identity/authz**: SQLAlchemy Core over SQLite or Postgres.
- **Per-tenant config**: flat JSON on disk, unchanged in shape from the original single-tenant design.
- **Graph engine**: [networkx](https://networkx.org/) `MultiDiGraph` — rules are nodes, `if_sid`/`if_matched_sid`/`if_group`/`if_matched_group` are edges.
- **Frontend**: React + TypeScript + Vite, built to static assets served directly by Flask.

See [`docs/RULEVIS_PRODUCT_GUIDE.md`](docs/RULEVIS_PRODUCT_GUIDE.md) for the full architecture reference, data model, module-by-module breakdown, and design rationale behind every major feature.

## Notes on rule condition parsing

While the Wazuh documentation defines `<if_level>` as another condition that creates a parent-child relationship, it isn't used in any built-in rules and is deliberately omitted here.

`<if_fts>` (*first time seen*) is also intentionally not treated as a parent-child relationship, since it doesn't create one.

## Acknowledgments

RuleVis began as a fork of [zbalkan/rulevis](https://github.com/zbalkan/rulevis) by Zafer Balkan, which introduced the core rule-parsing engine and force-directed graph visualization. This project builds substantially on that foundation — see [`LICENSE`](LICENSE) for the full attribution.

## License

MIT — see [`LICENSE`](LICENSE).
