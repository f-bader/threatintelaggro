# Data contracts

New article analyses use schema `1.2` and detection results use `1.1`. Existing article `1.0` and `1.1` records remain readable. The strict generation schemas in [AnalysisService.cs](../src/ThreatIntelAggro/AnalysisService.cs) define the implemented fields. [ArticleEvidenceValidator.cs](../src/ThreatIntelAggro/ArticleEvidenceValidator.cs) validates supporting excerpts and source references.

## Article analysis

Article output includes category and rationale, summary, findings, typed IOCs, references, mappings, detection potential, and coverage limitations. Mappings cover affected vendors and products, targeted industries and countries, actors, malware, campaigns, vulnerabilities, and MITRE techniques.

An IOC carries its type, original and normalized values, role, context, confidence, basis, and evidence. Roles are `malicious`, `suspicious`, `benign_context`, and `unknown`. Confidence is `low`, `medium`, or `high`. Basis is `source_reported` or `inferred`.

Product mappings include nullable `vendor_name`, `affected_versions`, and `affected_role` with values `exploited`, `abused`, `impersonated`, or `mentioned_affected`. Industry mappings use a nullable application taxonomy `sector_id`.

## Evidence

Evidence items contain `source_id`, `locator`, and an exact `excerpt`. Source IDs identify the supplied ledger. References use an inspection status of `fetched`, `search_excerpt`, `discovered_only`, or `inaccessible`. Search excerpts are tied to provider citations. Only fetched text and citation-backed excerpts support validated claims.

The app retains source snapshots and coverage limitations. Matching an excerpt establishes where text came from. Human review is still required to assess the interpretation and resulting detection.

## Detection output and export

Detection results have an `outcome` of `drafts_generated` or `no_supported_detection`, a reason, a detections list, and coverage information. Drafts contain a title, description, severity, rationale, KQL, tactic, techniques, behaviors and evidence, telemetry requirements, source IDs, and a playbook.

Severity is `informational`, `low`, `medium`, or `high`. Provider and validation failures are recorded as failures separately from a successful analysis that produces no detection.

[XDRConverter YAML export](../src/ThreatIntelAggro/DetectionYaml.cs) uses a serializer and the [bundled schema](../src/ThreatIntelAggro/Schemas/XDRConverter.schema.json). The upstream schema is pinned at commit `9c60aa8b653e89bf68ef4c318a92c1b62efe958b`. Export preserves the stored rule GUID and effective query, defaults the rule to disabled, and requires a supported tactic. JSON and KQL exports remain available independently.

## Application state

[AppDatabase.cs](../src/ThreatIntelAggro/AppDatabase.cs) owns persistence. Article read state, detection review state, IOC approvals, dismissals, exclusions, and analyst role overrides are stored separately from model output. Resetting an IOC classification restores its source role and preserves its approval state.

[IOC exports](USAGE.md#ioc-api) apply the current review and expiry rules. Full archived briefings preserve their snapshots. RSS applies current IOC approvals when read.
