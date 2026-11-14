# Threat Intel Aggro

A personal threat intelligence reader and detection idea workbench, built for local review and self-hosting in one Docker container.

The app includes RSS/Atom feed management and OPML import, scheduled polling, article analysis, public-source research, structured intelligence, IOC search/export, and AI-generated Defender XDR detections with KQL validation and XDRConverter YAML.

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md): architecture, workflows, UI, storage, deployment, milestones, and acceptance checks.
- [Data contracts](docs/DATA_CONTRACTS.md): article enrichment and detection output definitions.

Selected direction: C# / ASP.NET Core Razor Pages, SQLite, server-rendered HTML, handwritten CSS, and small vanilla JavaScript modules. No Python, Node.js, npm, frontend build pipeline, or Cloudflare dependency.

Run locally with `DOTNET_CLI_HOME="$PWD/.dotnet-cli" dotnet restore src/ThreatIntelAggro/ThreatIntelAggro.csproj`, then `AGGRO_DATA_DIR="$PWD/.local-data" DOTNET_CLI_HOME="$PWD/.dotnet-cli" dotnet run --project src/ThreatIntelAggro`. Open [http://localhost:5088](http://localhost:5088). The seeded Unit 42 feed is `https://unit42.paloaltonetworks.com/feed/` and imports entries from the last 14 days that the feed exposes. Run the container locally with `docker compose up --build`.

OpenAI is the primary AI provider. Azure OpenAI is an optional provider with explicit capability checks. Public source research and KQL assistance/validation use bounded tools; the MCP endpoint is `https://mcp.xdrinternals.com`.

Each detection includes downloadable Defender XDR custom-detection YAML following the [XDRConverter schema](https://github.com/f-bader/XDRConverter), alongside JSON and KQL exports. KQL is checked with the XDR Internals MCP service. Exported rules default to disabled and require owner review before deployment.

## IOC API

`GET /api/iocs` returns approved JSON indicators from articles published or first seen in the selected lookback period. The default is 7 days; `days` (or alias `n`) is clamped to 1–3650 days. Optional filters are `vendor`, `industry`, `type`, and `search`. Unapproved indicators are never returned unless `includeUnapproved=true` is explicitly set. The IOC page lets an analyst review and approve each item before it enters the default API response.

```text
GET http://localhost:5088/api/iocs?days=14&vendor=Google&industry=Government%20and%20public%20administration
```

The response contains `generatedUtc`, the applied `query`, `count`, and an `items` array. Each item includes the IOC value and normalized value, approval status, expiry time when configured, role, context, confidence, source article, affected vendors, targeted industries, and MITRE mappings. Default expiry is 90 days for IP addresses and URLs, 365 days for domains, hashes, email addresses, software IDs, file/host artifacts and generic indicators, and 730 days for certificate thumbprints. Change each lifetime in Settings; use 0 to disable expiry for that group. The endpoint has no authentication, matching the current single-user local app configuration.

Feeds have an optional **IOC pre approved** setting. When enabled, new IOC findings from that feed are approved after the full analysis completes, and existing extracted IOCs from its articles are approved when the setting is enabled. Turning it off does not revoke previous approvals.

To explicitly include indicators that still need review:

```text
GET http://localhost:5088/api/iocs?days=14&includeUnapproved=true
```
