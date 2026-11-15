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

Each detection includes downloadable Defender XDR custom-detection YAML following the [XDRConverter schema](https://github.com/f-bader/XDRConverter), alongside JSON and KQL exports. KQL is checked with the XDR Internals MCP service. Exported rules default to disabled and require owner review before deployment.

## IOC API

`GET /api/iocs` returns approved JSON indicators from articles published or first seen in the selected lookback period. The default is 7 days; `days` (or alias `n`) is clamped to 1–3650 days. Optional filters are `vendor`, `industry`, `type`, `search`, and `classification` (`malicious`, `suspicious`, or `context`). Context-only indicators remain excluded from the API. Only indicators marked malicious or suspicious are returned; benign and unknown observables are excluded even when previously approved. Unapproved actionable indicators are never returned unless `includeUnapproved=true` is explicitly set. The IOC page also shows benign, unknown, and unlabeled observables as context; those are excluded from the API and CSV. An analyst can classify an indicator as malicious or suspicious and reset that classification later; the source role is retained. Classification does not itself approve an indicator. If an indicator was already approved, classifying it makes it eligible for the API immediately. CSV downloads prefix formula-like cells with an apostrophe to protect spreadsheet users; the API keeps original values.

All `/api/*` routes require an `Authorization: Bearer <key>` header. Generate or rotate the key in Settings; it is displayed only once after rotation and stored as a one-way hash. The previous key remains valid for 24 hours after rotation. `/health` is unauthenticated for container health checks. Entra ID sign-in and UI access are expected to be handled by the hosting environment or reverse proxy. The UI's `/internal/*` status endpoint should be protected by the same front-door access control as the rest of the UI.

```text
curl -H "Authorization: Bearer $AGGRO_API_KEY" \
  "http://localhost:5088/api/iocs?days=14&vendor=Google&industry=Government%20and%20public%20administration"
```

The response contains `generatedUtc`, the applied `query`, `count`, and an `items` array. Each item includes the IOC value and normalized value, approval status, expiry time when configured, role, context, confidence, source article, affected vendors, targeted industries, and MITRE mappings. Default expiry is 90 days for IP addresses and URLs, 365 days for domains, hashes, email addresses, software IDs, file/host artifacts and generic indicators, and 730 days for certificate thumbprints. Change each lifetime in Settings; use 0 to disable expiry for that group.

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
