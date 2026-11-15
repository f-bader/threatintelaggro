# Threat Intel Aggro — data contracts

These are implementation specifications for versioned JSON Schema contracts. The implementation milestone will materialize them as strict schemas and C# records, using the provider-supported JSON Schema subset for generation and full local validation before persistence. Examples below are synthetic and contain no generated detection query.

**Implementation status:** New article and detection outputs use schema `1.1`; previously saved `1.0` output remains readable. The implemented schemas are defined in `AnalysisService.cs`, and `ArticleEvidenceValidator.cs` verifies fetched or citation-backed search-excerpt source IDs and exact excerpts for summaries, findings, indicators, mappings and detection behaviors. A search excerpt is stored and displayed as `search_excerpt`; it does not imply that the full page was fetched. The richer mapping specializations, taxonomy checks and several additional detection fields described below remain design targets rather than implemented guarantees. An exact excerpt establishes provenance, not that a claim or KQL query is correct.

## Shared conventions

- Schema versions start at `1.0`. Changing a field's meaning requires a new version, with a migration/projection strategy.
- All listed fields are required unless explicitly marked application-only. Use `null` for a permitted unknown scalar and `[]` for an empty collection. Do not omit unsupported mappings or invent placeholder names.
- Objects reject unknown properties. Strings have bounded lengths and collections have maximum counts in the materialized schema. The AI output is data, never HTML or executable instructions.
- `confidence` is `low`, `medium`, or `high`: an assessment, not a statistical probability. It is independent of `basis`, which is `source_reported` or `inferred`.
- Every factual mapping, IOC, and detection behavior has evidence. Inferences must explain the link. Unsupported attribution stays empty rather than becoming an inferred actor.
- Evidence item: `{ "source_id": "src_…", "locator": "paragraph 4", "excerpt": "short supporting text" }`. `locator` may identify paragraphs, PDF pages, or immutable code path/line ranges. Verify the excerpt exists in the supplied snapshot; treat normalization differences explicitly. Excerpts are short, not a substitute for the stored source.
- The application allocates source IDs and records retrieved content. The model may only cite known source IDs. All reference URLs/titles/statuses must match the source ledger; never trust invented model URLs as fetched evidence.
- For search-only evidence, label `search_excerpt` and tie it to a URL citation returned by the search provider; it cannot claim the full page or code was parsed. An inaccessible source may be a reference but cannot support a claim of inspected code behavior.
- Display confidence, basis, evidence, and truncation together. Empty fields mean no supported information, not proof that a threat does not exist.

## 1. Article enrichment output

| Field | Type / semantics |
| --- | --- |
| schema_version | Constant `1.0` |
| language | Source language code or `null` |
| summary | Object: `headline`, `overview`, `key_findings[]`; each finding contains `text`, `basis`, `confidence`, `evidence[]` |
| iocs | List of typed indicators with context and evidence |
| references | Original article and discovered related report/document/code references |
| mitre_mappings | Supported tactic/technique/sub-technique mappings |
| industries | Targeted victim-sector mappings |
| threat_actors | Actor names and source-reported aliases, without guessed attribution |
| vendors | Affected product vendors, not reporting publishers |
| products | Affected products and supported vendor/version relationships |
| malware | Malware family/tool names with role and attribution basis |
| campaigns | Named campaigns, only when supported |
| vulnerabilities | CVE IDs and source-supported affected-product relationships |
| targeted_countries | ISO 3166-1 alpha-2 country codes and names; explicit geography only |
| detection_assessment | Object: `potential` (`sufficient`, `insufficient`, `uncertain`), `reason`, `evidence[]`; advisory, not a substitute for stage 2 |
| coverage | Research/extraction limitations and uninspected discovered sources |

An IOC item contains `type`, `value`, `normalized_value`, `role`, `context`, `confidence`, `basis`, and `evidence[]`. Types initially include `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `file_name`, `file_path`, `registry_key`, `mutex`, and `certificate_thumbprint`. Role is `malicious`, `suspicious`, `benign_context`, or `unknown`. Only malicious/suspicious items enter the default actionable IOC list; preserve other observables in the JSON and a separate UI section. A file path or name alone is not automatically malicious.

Validate IPs/hashes syntactically; preserve original defanged values while normalizing explicitly recognized forms. Do not extract every hostname or hexadecimal example into an actionable IOC. Record indicator context, source, and first-seen article time; do not invent threat observation dates.

A reference item contains `source_id`, `url`, `title`, `kind` (`original`, `related_report`, `code`, `document`), `inspection_status` (`fetched`, `search_excerpt`, `discovered_only`, `inaccessible`), and `relevance`. Source ledger metadata additionally stores fetched time, content hash, MIME type, redirect chain, truncation flags, error/skipped reason, and immutable repository revision where available. Those ledger fields are application-owned.

A common mapping item contains `name`, `confidence`, `basis`, `rationale`, and `evidence[]`. Specializations add:

| Mapping | Additional fields / rules |
| --- | --- |
| MITRE | `attack_domain` (initially `enterprise`), `technique_id`, `technique_name`, `tactic_ids[]`; validate IDs against a bundled versioned MITRE taxonomy, including sub-techniques; the application stores taxonomy version |
| Industry | `sector_id`, from the app taxonomy below; the mapped role is targeted victim sector |
| Actor | `aliases[]`; preserve cited names without merging disputed identities |
| Vendor | `role` fixed to `affected_product_vendor` |
| Product | `vendor_name` nullable, `affected_versions[]`, `affected_role` (`exploited`, `abused`, `impersonated`, `mentioned_affected`) |
| Malware/tool | `role` (`malware`, `offensive_tool`, `legitimate_tool_abused`, `unknown`), `aliases[]` |
| Campaign | `aliases[]` |
| Vulnerability | `cve_id`, `affected_products[]`; validate CVE format, but do not imply independent exploitability verification |
| Country | `country_code`; a headquarters location does not establish targeting |

Use this small application-owned sector taxonomy, with stable IDs and editable display labels: `government`, `defense`, `healthcare`, `financial_services`, `technology`, `telecommunications`, `energy`, `utilities`, `manufacturing`, `transportation`, `retail`, `education`, `media`, `professional_services`, `hospitality`, `agriculture`, `nonprofit`, and `other`. Multiple sectors may apply; record the original source phrase in the rationale. `other` requires a specific rationale. Empty means unknown. This taxonomy is a convenience, not a claim to implement a formal industry standard.

`coverage` contains `limitations[]` (plain strings), `uninspected_source_ids[]`, and `conflicting_claims[]`. A conflicting claim contains `topic`, `description`, and `source_ids[]`. Do not silently resolve disagreements between sources into certainty.

Minimal synthetic article output:

```json
{
  "schema_version": "1.0",
  "language": "en",
  "summary": {
    "headline": "Synthetic source with insufficient technical detail",
    "overview": "The source is a fixture for the ingestion pipeline and does not establish a supported threat attribution or detection opportunity.",
    "key_findings": []
  },
  "iocs": [],
  "references": [
    {
      "source_id": "src_fixture_001",
      "url": "https://example.org/fixture",
      "title": "Synthetic fixture",
      "kind": "original",
      "inspection_status": "fetched",
      "relevance": "Original fixture document."
    }
  ],
  "mitre_mappings": [],
  "industries": [],
  "threat_actors": [],
  "vendors": [],
  "products": [],
  "malware": [],
  "campaigns": [],
  "vulnerabilities": [],
  "targeted_countries": [],
  "detection_assessment": {
    "potential": "insufficient",
    "reason": "No supported behavior or telemetry is present in this fixture.",
    "evidence": []
  },
  "coverage": {
    "limitations": ["Synthetic example only; no public research was performed."],
    "uninspected_source_ids": [],
    "conflicting_claims": []
  }
}
```

## 2. Detection generation output

Stage 2 returns an object with `schema_version`, `outcome`, `reason`, `detections[]`, and `coverage`. `outcome` is `drafts_generated` or `no_supported_detection`. Require one to three detections for the former and an empty array for the latter. Operational/model failures are job states, never disguised as a no-detection decision.

Each detection object contains:

| Field | Type / semantics |
| --- | --- |
| local_key | Unique stable key within this article's generation output |
| alert_title | Proposed Microsoft Defender XDR / unified custom-detection title |
| alert_description | Clear proposed alert description |
| severity | `informational`, `low`, `medium`, `high` |
| rationale | Why this observed behavior may be detectable |
| confidence | Shared confidence enum |
| behaviors | List of `{ description, basis, confidence, evidence[] }` |
| mitre_mappings | Same mapping structure as the article contract |
| target_environment | `unified` |
| telemetry | Object: `tables[]`, `required_columns[]`, `connectors_or_products[]`, `assumptions[]`, `known_gaps[]`; required column item has `table` and `columns[]` |
| kql | Nonempty query text; local maximum length and table/schema checks apply |
| rule_guidance | Object: `intended_use` (`hunting`, `custom_detection`, `both`), `suggested_frequency`, `lookback`, `entity_columns[]`, `limitations[]`; frequency/lookback nullable when unknown |
| false_positives | String list of likely benign explanations |
| tuning | String list of suggested thresholds/exclusions to review, never automatically applied |
| playbook | Object: `title`, `triage_steps[]`, `investigation_steps[]`, `response_options[]`, `escalation_criteria[]`; response options are ideas, not actions taken |
| source_ids | Supporting known source IDs |
| limitations | String list, including truncation, uncertain telemetry, or unsupported platform behavior |

No invented table/column is accepted as validated. Detection can span XDR or Sentinel tables only if table availability and join/entity requirements are explicit. Custom-detection result shape is evaluated for the selected tables and current platform guidance, not one universal hard-coded projection. Code evidence should explain the actual observable side effect; a function name alone is insufficient.

Example of the explicit no-detection outcome:

```json
{
  "schema_version": "1.0",
  "outcome": "no_supported_detection",
  "reason": "The supplied evidence contains no observable behavior that supports a query.",
  "detections": [],
  "coverage": {
    "limitations": ["Synthetic fixture, not a completed live analysis."],
    "uninspected_source_ids": []
  }
}
```

The application links each saved detection to its article, source snapshots, generation run, and review data. A stage-2 result is saved even when no detection is produced, so the UI distinguishes deliberate abstention from a missing or failed job.

## 2a. XDRConverter YAML export

For each saved detection, generate one downloadable UTF-8 `.yaml` document from the current effective detection. Follow the upstream [`CustomDetection.schema.json` and property mapping](https://github.com/f-bader/XDRConverter). Pin the upstream schema to a reviewed commit in the implementation; do not silently drift as `main` changes. Keep the original KQL and JSON exports available.

Map the internal fields as follows:

| XDRConverter YAML field | Source / export rule |
| --- | --- |
| `guid` | Stable UUID stored when the detection is first created; do not issue a new value each export |
| `ruleName` | `alert_title`, trimmed to converter/XDR supported length |
| `description` | `alert_description` |
| `status` | `disabled` by default; owner may explicitly choose `enabled` when exporting |
| `frequency` | `suggested_frequency` only when converter accepts it (`1H`, `3H`, `12H`, `24H`); otherwise explicit `24H` default shown in the export preview |
| `alertTitle` | `alert_title` |
| `alertSeverity` | `severity`, mapped to `Informational`, `Low`, `Medium`, or `High` |
| `alertDescription` | `alert_description` |
| `alertRecommendedAction` | Concise playbook recommendation, when available and within schema limits; full playbook remains in JSON |
| `tactics` | One primary XDR-supported tactic with supported techniques/sub-techniques |
| `queryText` | Current effective KQL, exactly matching the query hash whose validation status is displayed |
| `detectorId`, `entityMappings`, `customDetails`, `organizationalScope`, `actions` | Omit unless explicitly populated with validated data; never invent values |

XDRConverter documents a single tactic entry for the detection action template. When the internal mapping contains techniques under more than one tactic, select the primary supported tactic deterministically from the mapping, emit its associated techniques, and include a visible export warning listing omitted tactic mappings. Do not imply the YAML fully represents internal MITRE coverage. If no compatible tactic/technique is available, still allow a disabled YAML export with `tactics` omitted if the pinned schema permits it; otherwise explain the schema rejection and keep JSON/KQL export available.

Use a real YAML serializer and the upstream schema to quote strings and preserve multiline KQL as a literal block. Never hand-build YAML with string concatenation. The default app image does not need PowerShell or XDRConverter installed. Keep optional converter checks in an integration-test environment where PowerShell 7 and the module's YAML dependency can be installed. Validate representative output through `ConvertTo-CustomDetectionJson`; do not invoke `Deploy-CustomDetection` from the application.

The exported file is a reviewed draft and can be converted by XDRConverter. Creating it does not deploy a detection. The enable/disable export choice does not change the detection's review status or mark it implemented.

## 3. Application-owned metadata and validation

The AI cannot set IDs, read state, review status, implemented status, archive timestamps, validation success, provider usage, or tenant-test results. These are stored separately and included in an export envelope:

| Field group | Contents |
| --- | --- |
| Identity/provenance | Article/detection IDs, canonical source URL, publication/ingestion/completion UTC times, feed membership, schema/prompt version, provider/model/effort, source snapshot hashes |
| Usage | Input/output/reasoning/cached tokens when reported; actual search/MCP/fetch counts; provider request/response IDs and latency; unknown usage remains null |
| Article state | `is_read`, `read_at`, bookmark, notes, tags |
| Detection review | `status`: `new`, `reviewing`, `accepted`, `rejected`, `implemented`; `archived_at` nullable; notes, tags, implementation URL/date nullable |
| KQL validation | `state`: `pending`, `valid`, `invalid`, `unavailable`, `unsupported`; query hash, MCP server/tool identity, environment/profile/schema version if returned, time, raw bounded diagnostics |
| Rule shape | `state`: `not_checked`, `passed`, `failed`, `not_applicable`; projected entities, limitations, diagnostics |
| Tenant testing | `state`: `not_tested`, `passed`, `failed`; owner notes and timestamp; manual only in version one |
| Revisions | Immutable machine output plus effective owner-edited JSON/KQL and edit timestamps; validation tied to the current query hash |

A validation result is valid only for the exact query hash submitted. Preserve old diagnostics as history but do not display them as applying to edited KQL. Archiving retains status and all evidence. Manually setting implemented does not change validation or tenant-test state.

## 4. Contract enforcement sequence

1. Reject provider refusals, incomplete outputs, wrong schema versions, and malformed JSON before creating any completed analysis record.
2. Validate JSON Schema, typed field bounds, enums, conditional stage-2 outcome rules, and local IDs.
3. Validate evidence existence, excerpt/locator coverage, referenced URLs and source inspection status, ATT&CK IDs, IOC syntax, CVE format, country/sector IDs, and uniqueness constraints.
4. Check that factual claims do not cite only inaccessible/uninspected sources. An inference can be uncertain but still needs identified support.
5. Permit one bounded repair using concrete diagnostics; otherwise preserve the failed run for diagnosis and mark the job failed.
6. Persist validated output plus relational projections atomically; never partially publish mappings from an invalid JSON object.
7. For detections, store draft validity separately from independently obtained MCP validation and custom-rule diagnostics. A structurally valid draft can still have invalid KQL and must be visibly labeled that way.
8. Apply the same structural checks to manual edits. Manual edits preserve the original output and invalidate affected derived validation/projections.

Schema conformance and source matching cannot prove that every model interpretation is correct. Evidence links, explicit uncertainty, owner review, and a separate tenant-test state make that limitation visible.
