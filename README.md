# Threat Intel Aggro

A personal threat intelligence reader and detection idea workbench, built for local review and self-hosting in one Docker container.

The app includes RSS/Atom feed management and OPML import, scheduled polling, article analysis, public-source research, structured intelligence, IOC search/export, and AI-generated Defender XDR detections with KQL validation and XDRConverter YAML.

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md): architecture, workflows, UI, storage, deployment, milestones, and acceptance checks.
- [Data contracts](docs/DATA_CONTRACTS.md): article enrichment and detection output definitions.

Selected direction: C# / ASP.NET Core Razor Pages, SQLite, server-rendered HTML, handwritten CSS, and small vanilla JavaScript modules. No Python, Node.js, npm, frontend build pipeline, or Cloudflare dependency.

Run locally with `DOTNET_CLI_HOME="$PWD/.dotnet-cli" dotnet restore src/ThreatIntelAggro/ThreatIntelAggro.csproj`, then `AGGRO_DATA_DIR="$PWD/.local-data" DOTNET_CLI_HOME="$PWD/.dotnet-cli" dotnet run --project src/ThreatIntelAggro`. Open [http://localhost:5088](http://localhost:5088). The seeded Unit 42 feed is `https://unit42.paloaltonetworks.com/feed/` and imports entries from the last 14 days that the feed exposes. Build the source container locally with `docker compose -f compose.yaml -f compose.dev.yaml up --build`.

The deployment Compose file pulls the released image from GitHub Container Registry. See [release and repository setup](docs/RELEASING.md) for release tags, image tags, and the required PR/CI ruleset.

The container runs as a non-root user and prepares `/data` for its persistent Compose volume. If you created that volume with an older image and startup fails with `Access to the path '/data/keys' is denied`, repair its ownership once, then start the app again:

```sh
docker compose run --rm --user 0:0 --entrypoint sh threat-intel-aggro -c 'chown -R "$APP_UID:$APP_UID" /data'
docker compose up -d
```

This keeps the existing database and other volume contents. For a bind mount instead of the named volume, make the host directory writable by the container's app UID (1654).

OpenAI is the primary AI provider. Azure OpenAI is an optional provider with explicit capability checks. Public source research and KQL assistance/validation use bounded tools; the MCP endpoint is `https://mcp.xdrinternals.com`.

## Daily threat briefings

Briefings is the default start tab; Inbox remains available as its own tab. In Settings, follow affected vendors and industries from analyzed article metadata or add custom names. Entries can be disabled without removing them. Briefings match analyzed articles in the previous 24-hour UTC window using normalized and conservative fuzzy matching, and preserve each match in the archived snapshot.

The background scheduler defaults to 06:00 UTC, backfills missed daily windows, and waits for in-progress article analyses before closing a window. It does not create a briefing when no followed vendor or industry matches an analyzed article. A briefing includes an AI-written executive summary, links to applicable articles with exact/fuzzy match reasons, relevant unarchived detection drafts, and IOC counts by type and classification without raw values. The system prompt is editable in Settings; clearing it and saving restores the displayed default. Generation uses the configured AI model. Settings also provide manual generation and a schedule enable/disable control.

Each briefing is archived. Markdown and light-design PDF downloads are available. Settings can generate or rotate a full-archive RSS URL at `/briefings/rss/<random-id>`. The random ID is stored as a hash and shown only once; treat the URL as a secret. The RSS endpoint is unauthenticated at the app layer for feed readers, but its random ID is required. When the deployment proxy normally requires sign-in, exempt only `/briefings/rss/*` from that sign-in rule; keep `/`, `/Settings`, `/Inbox`, `/briefings/<id>`, and the other UI routes protected. Verify that missing or invalid RSS IDs return 404.

Detections have JSON and KQL downloads. XDRConverter YAML is generated with a YAML serializer and checked against the [XDRConverter schema](https://github.com/f-bader/XDRConverter) pinned at commit `9c60aa8b653e89bf68ef4c318a92c1b62efe958b`. A supported ATT&CK tactic is required for YAML export; older drafts without one can still be downloaded as KQL or JSON. KQL validation uses the XDR Internals MCP service when available. Review the validation status and source evidence before using a draft; evidence matching does not establish that the detection is correct. Exported rules default to disabled.

## Backups and restore

The app creates a SQLite-consistent backup at startup if there is no backup for the current UTC day, and checks hourly thereafter. Backups live in `/data/backups` in the container (or `backups` under `AGGRO_DATA_DIR` locally) and include the database and Data Protection keys. Each has a SHA-256 manifest and a checked SQLite snapshot. The app retains the latest snapshot for each of seven days and one per older week for four weeks. Backup failures are reported in the application logs. Backups share the production volume, so also copy them to a separate, access-controlled location; they contain sensitive data and encryption keys.

Restore is deliberately limited to a new directory. Stop the application before switching to restored data, retain the existing data directory, and verify the result before putting it into service. For a local installation, run the built application with `dotnet ThreatIntelAggro.dll --restore-backup /path/to/backup /path/to/new-data-directory`. In Compose, an example is:

```sh
docker compose run --rm --entrypoint dotnet threat-intel-aggro ThreatIntelAggro.dll --restore-backup /data/backups/<backup-directory> /data/restored-check
```

The command verifies the manifest, file hashes and database before copying into a new destination; it never replaces the current database. Restore the Data Protection keys along with the database when switching data directories. Test the restored copy separately before changing the production volume.

## IOC API

`GET /api/iocs` returns approved JSON indicators from articles published or first seen in the selected lookback period. The default is 7 days; `days` (or alias `n`) is clamped to 1–3650 days. Optional filters are `vendor`, `industry`, `type`, `search`, and `classification` (`malicious`, `suspicious`, or `context`). Context-only indicators remain excluded from the API. Only indicators marked malicious or suspicious are returned; benign and unknown observables are excluded even when previously approved. Unapproved actionable indicators are never returned unless `includeUnapproved=true` is explicitly set. The IOC page also shows benign, unknown, and unlabeled observables as context; those are excluded from the API and CSV. An analyst can classify an indicator as malicious or suspicious and reset that classification later; the source role is retained. Classification does not itself approve an indicator. If an indicator was already approved, classifying it makes it eligible for the API immediately. CSV downloads prefix formula-like cells with an apostrophe to protect spreadsheet users; the API keeps original values.

All `/api/*` routes require an `Authorization: Bearer <key>` header. Generate or rotate the key in Settings; it is displayed only once after rotation and stored as a one-way hash. The previous key remains valid for 24 hours after rotation. `/health` is unauthenticated for container health checks. Entra ID sign-in and UI access are expected to be handled by the hosting environment or reverse proxy. The UI's `/internal/*` status endpoint should be protected by the same front-door access control as the rest of the UI.

```text
curl -H "Authorization: Bearer $AGGRO_API_KEY" \
  "http://localhost:5088/api/iocs?days=14&vendor=Google&industry=Government%20and%20public%20administration"
```

The response contains `generatedUtc`, the applied `query`, `count`, and an `items` array. Each item includes the IOC value and normalized value, approval status, expiry time when configured, role, context, confidence, source article, affected vendors, targeted industries, and MITRE mappings. Default expiry is 90 days for IP addresses and URLs, 365 days for domains, hashes, email addresses, software IDs, file/host artifacts and generic indicators, and 730 days for certificate thumbprints. Change each lifetime in Settings; use 0 to disable expiry for that group.

The indicator page summarizes context-only, unapproved, expired, excluded and archived indicators within the chosen time range; categories may overlap. Select individual context-only indicators to classify them together after review. Expired and excluded indicators are not shown in the active list; use Settings to inspect the expiry and exclusion rules.

Choose the AI model or deployment ID and reasoning effort in Settings. The OpenAI model list can be refreshed without generating a response; Azure deployment IDs can be entered manually. Optional per-stage settings override the defaults for research, article analysis, detection generation, or KQL repair. New installations need a model selection before analysis. Existing installations import their prior effective model and effort settings once, and each analysis retains its settings across retries. Provider and model capability errors appear on the affected article; credentials remain in deployment configuration and are not stored in the application database.

Feeds have an optional **IOC pre approved** setting. When enabled, new IOC findings from that feed are approved after the full analysis completes, and existing indicators from completed, evidence-validated analyses are approved when the setting is enabled. Analyses created before evidence validation was introduced are not automatically approved; review their indicators manually. Turning it off does not revoke previous approvals.

To explicitly include indicators that still need review:

```sh
curl -H "Authorization: Bearer $AGGRO_API_KEY" \
  "http://localhost:5088/api/iocs?days=14&includeUnapproved=true"
```

### NGINX reverse proxy

Compose publishes the app on host loopback only (`127.0.0.1:5088`). NGINX should forward `X-Forwarded-For` and `X-Forwarded-Proto`. Set `AGGRO_TRUSTED_PROXY_IPS` in the Compose `.env` file to the address of the proxy as seen from inside the app container; when NGINX runs on the host, this is often the Docker bridge gateway. The app trusts one forwarded-header hop and ignores forwarded headers from all addresses that are not explicitly listed. Leave the setting empty when no trusted proxy is configured, and do not use a broad subnet or `0.0.0.0`.

To find the bridge gateway, inspect the Compose network with `docker network inspect <network-name>` and use its `Gateway` address. For example:

```dotenv
AGGRO_TRUSTED_PROXY_IPS=172.18.0.1
```

Restart the app container after changing this value. If NGINX runs in Docker on a shared Compose network, set the NGINX container's fixed network address instead.

Verify the deployed front door independently: requests to `/`, `/Settings`, `/Inbox`, `/Iocs`, `/Detections`, `/briefings/<id>`, `/internal/*` and `/api/*` without the intended credentials must be denied. The tokenized `/briefings/rss/<random-id>` route is the only UI-related unauthenticated exception; invalid IDs must return 404. `/health` may remain available for health checks. Confirm authenticated requests work and that the app port cannot be reached directly from an untrusted network. Verify that the proxy removes client-supplied forwarding headers and supplies its own, and test these checks again whenever the proxy or network configuration changes. The app does not implement UI sign-in itself.
