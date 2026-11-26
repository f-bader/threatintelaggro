using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public static class ArticleEvidenceValidator
{
    public sealed record EvidenceMismatch(string Path, string SourceId, string Excerpt, string SourceContent);

    public sealed class EvidenceExcerptMismatchException(string message, IReadOnlyList<EvidenceMismatch> mismatches) : InvalidOperationException(message)
    {
        public IReadOnlyList<EvidenceMismatch> Mismatches { get; } = mismatches;
    }

    public static void Validate(string json, JsonArray sources, JsonObject schema) => _ = ValidateAndSanitize(json, sources, schema);

    public static string ValidateAndSanitize(string json, JsonArray sources, JsonObject schema)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Article output is empty.");
        CheckSchema(root, schema, "article");
        if (root["schema_version"]!.GetValue<string>() != "1.2") Fail("Unsupported article schema version.");
        var ledger = sources.ToDictionary(x => x!["source_id"]!.GetValue<string>(), x => x!, StringComparer.Ordinal);
        foreach (var reference in root["references"]!.AsArray())
        {
            var id = reference!["source_id"]!.GetValue<string>();
            if (!ledger.TryGetValue(id, out var source)) Fail("Reference names an unknown source.");
            foreach (var property in new[] { "url", "title", "kind", "inspection_status" })
                if (reference[property]!.GetValue<string>() != source![property]!.GetValue<string>()) Fail("Reference metadata does not match the source ledger.");
        }
        ValidateEvidence(root["summary"]!["evidence"]!.AsArray(), ledger, true, "/summary/evidence");
        var findingIndex = 0;
        foreach (var finding in root["summary"]!["key_findings"]!.AsArray())
        {
            CheckAssessment(finding!);
            if (string.IsNullOrWhiteSpace(finding!["text"]!.GetValue<string>())) Fail("A key finding cannot be empty.");
            ValidateEvidence(finding["evidence"]!.AsArray(), ledger, true, $"/summary/key_findings/{findingIndex++}/evidence");
        }
        ValidateEvidence(root["detection_assessment"]!["evidence"]!.AsArray(), ledger, root["detection_assessment"]!["potential"]!.GetValue<string>() == "sufficient", "/detection_assessment/evidence");
        var iocIndex = 0;
        foreach (var item in root["iocs"]!.AsArray())
        {
            var ioc = item!;
            var type = ioc["type"]!.GetValue<string>();
            var value = ioc["value"]!.GetValue<string>();
            var normalized = ioc["normalized_value"]?.GetValue<string>() ?? IndicatorNormalization.Normalize(value);
            if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || string.IsNullOrWhiteSpace(ioc["context"]!.GetValue<string>())) Fail("IOC value and context are required.");
            var role = ioc["role"]!.GetValue<string>();
            if (role is not ("malicious" or "suspicious" or "benign_context" or "unknown")) Fail($"iocs[{iocIndex}].role has unsupported value '{role}'. Allowed: malicious, suspicious, benign_context, unknown.");
            CheckAssessment(ioc);
            if (!IndicatorNormalization.Matches(type, value, ioc["normalized_value"]?.GetValue<string>())) Fail("Normalized IOC does not match its original value.");
            CheckIndicator(type, normalized);
            var evidence = ioc["evidence"]!.AsArray();
            if (evidence.Count == 0) Fail("IOC evidence is required.");
            var valueFound = false;
            for (var evidenceIndex = 0; evidenceIndex < evidence.Count; evidenceIndex++)
            {
                var entry = evidence[evidenceIndex];
                var id = entry!["source_id"]!.GetValue<string>();
                var excerpt = entry["excerpt"]!.GetValue<string>();
                if (!ledger.TryGetValue(id, out var source) || !IsReadable(source)) Fail("IOC cites an unknown, inaccessible, or undiscovered source.");
                var content = source!["content"]!.GetValue<string>();
                if (string.IsNullOrWhiteSpace(entry["locator"]!.GetValue<string>()) || string.IsNullOrWhiteSpace(excerpt) || excerpt.Length > 2000) Fail("IOC evidence is missing a locator or excerpt.");
                if (!EvidenceContains(content, excerpt)) throw Mismatch($"/iocs/{iocIndex}/evidence/{evidenceIndex}", id, excerpt, content);
                if (ContainsIndicatorText(excerpt, value)) valueFound = true;
            }
            if (!valueFound) Fail($"iocs[{iocIndex}] value '{value}' is absent from its cited evidence excerpts.");
            iocIndex++;
        }
        var sectorIds = new HashSet<string>(["government","defense","healthcare","financial_services","technology","telecommunications","energy","utilities","manufacturing","transportation","retail","education","media","professional_services","hospitality","agriculture","nonprofit","other"], StringComparer.Ordinal);
        foreach (var industry in root["industries"]!.AsArray())
        {
            var sectorId = industry!["sector_id"];
            if (sectorId is not null && sectorId.GetValueKind() != System.Text.Json.JsonValueKind.Null && !sectorIds.Contains(sectorId.GetValue<string>())) Fail("Industry sector_id is not in the supported taxonomy.");
        }
        foreach (var field in new[] { "mitre_mappings", "industries", "threat_actors", "vendors", "products", "malware", "campaigns", "vulnerabilities", "targeted_countries" })
        {
            var mappings = root[field]!.AsArray();
            for (var index = mappings.Count - 1; index >= 0; index--)
            {
                try
                {
                    var mapping = mappings[index]!;
                    CheckAssessment(mapping);
                    var evidence = mapping["evidence"]!.AsArray();
                    if (evidence.Count == 0) Fail("Mapping evidence is required.");
                    ValidateEvidence(evidence, ledger, true, $"/{field}/{index}/evidence");
                }
                catch (InvalidOperationException)
                {
                    // Optional taxonomy mappings must not block otherwise valid article analysis.
                    // Drop the unsupported mapping so unverifiable claims never reach the saved result.
                    mappings.RemoveAt(index);
                }
            }
        }
        return root.ToJsonString();
    }

    public static void ValidateDetection(string json, JsonArray sources, JsonObject schema)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Detection output is empty.");
        CheckSchema(root, schema, "detection");
        if (root["schema_version"]!.GetValue<string>() != "1.1") Fail("Unsupported detection schema version.");
        var ledger = sources.ToDictionary(x => x!["source_id"]!.GetValue<string>(), x => x!, StringComparer.Ordinal);
        var detections = root["detections"]!.AsArray();
        var outcome = root["outcome"]!.GetValue<string>();
        if ((outcome == "drafts_generated" && detections.Count is < 1 or > 3) || (outcome == "no_supported_detection" && detections.Count != 0)) Fail("Detection outcome and draft count disagree.");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        for (var detectionIndex = 0; detectionIndex < detections.Count; detectionIndex++)
        {
            var detection = detections[detectionIndex];
            var key = detection!["local_key"]!.GetValue<string>();
            if (string.IsNullOrWhiteSpace(key) || !keys.Add(key) || string.IsNullOrWhiteSpace(detection["alert_title"]!.GetValue<string>()) || string.IsNullOrWhiteSpace(detection["kql"]!.GetValue<string>())) Fail("Detection keys, titles and queries must be present, and keys must be unique.");
            if (detection!["severity"]!.GetValue<string>() is not ("informational" or "low" or "medium" or "high")) Fail("Invalid detection severity.");
            var cited = new HashSet<string>(StringComparer.Ordinal);
            var behaviors = detection["behaviors"]!.AsArray();
            if (behaviors.Count == 0) Fail("Detection behavior evidence is required.");
            for (var behaviorIndex = 0; behaviorIndex < behaviors.Count; behaviorIndex++)
            {
                var behavior = behaviors[behaviorIndex];
                CheckAssessment(behavior!);
                if (string.IsNullOrWhiteSpace(behavior!["description"]!.GetValue<string>())) Fail("Detection behavior cannot be empty.");
                cited.UnionWith(ValidateEvidence(behavior["evidence"]!.AsArray(), ledger, true, $"/detections/{detectionIndex}/behaviors/{behaviorIndex}/evidence"));
            }
            for (var mappingIndex = 0; mappingIndex < detection["mitre_mappings"]!.AsArray().Count; mappingIndex++)
            {
                var mapping = detection["mitre_mappings"]![mappingIndex];
                CheckAssessment(mapping!);
                cited.UnionWith(ValidateEvidence(mapping!["evidence"]!.AsArray(), ledger, true, $"/detections/{detectionIndex}/mitre_mappings/{mappingIndex}/evidence"));
            }
            var declared = detection["source_ids"]!.AsArray().Select(x => x!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
            if (declared.Count == 0 || declared.Any(id => !ledger.TryGetValue(id, out var source) || !IsReadable(source)) || !cited.IsSubsetOf(declared)) Fail("Detection source IDs do not match readable evidence.");
        }
    }

    private static HashSet<string> ValidateEvidence(JsonArray evidence, Dictionary<string, JsonNode> ledger, bool required, string path)
    {
        if (required && evidence.Count == 0) Fail("Evidence is required.");
        var cited = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < evidence.Count; index++)
        {
            var item = evidence[index];
            var id = item!["source_id"]!.GetValue<string>();
            var excerpt = item["excerpt"]!.GetValue<string>();
            if (!ledger.TryGetValue(id, out var source) || !IsReadable(source)) Fail("Evidence cites an unknown, inaccessible, or undiscovered source.");
            if (string.IsNullOrWhiteSpace(item["locator"]!.GetValue<string>()) || string.IsNullOrWhiteSpace(excerpt) || excerpt.Length > 2000) Fail("Evidence is missing a locator or excerpt.");
            var content = source!["content"]!.GetValue<string>();
            if (!EvidenceContains(content, excerpt)) throw Mismatch($"{path}/{index}", id, excerpt, content);
            cited.Add(id);
        }
        return cited;
    }

    private static bool IsReadable(JsonNode source) => source["inspection_status"]?.GetValue<string>() is "fetched" or "search_excerpt";

    private static bool EvidenceContains(string source, string excerpt, StringComparison comparison = StringComparison.OrdinalIgnoreCase)
    {
        if (source.Contains(excerpt, comparison)) return true;
        var normalizedSource = NormalizeEvidenceText(source);
        var normalizedExcerpt = NormalizeEvidenceText(excerpt);
        return normalizedExcerpt.Length > 0 && normalizedSource.Contains(normalizedExcerpt, comparison);
    }

    private static string NormalizeEvidenceText(string text)
    {
        // Source bodies are flattened from HTML while the model sees their serialized text.
        // Decode entities and normalize common Unicode/whitespace differences before checking
        // that a citation is still a contiguous excerpt of the stored source.
        var normalized = WebUtility.HtmlDecode(text).Normalize(System.Text.NormalizationForm.FormKC)
            .Replace("\u0019", "'", StringComparison.Ordinal)
            .Replace('’', '\'').Replace('‘', '\'').Replace('“', '"').Replace('”', '"').Replace('„', '"')
            .Replace('–', '-').Replace('—', '-').Replace('−', '-')
            .Replace("…", "...", StringComparison.Ordinal)
            .Replace("\u00AD", "", StringComparison.Ordinal)
            .Replace("\u200B", "", StringComparison.Ordinal)
            .Replace("\u200C", "", StringComparison.Ordinal)
            .Replace("\u200D", "", StringComparison.Ordinal)
            .Replace("\uFEFF", "", StringComparison.Ordinal);
        normalized = Regex.Replace(normalized, @"\s+", " ").Trim();
        normalized = Regex.Replace(normalized, @"\s+([,.;:!?])", "$1");
        normalized = Regex.Replace(normalized, @"\s*-\s*", "-");
        return normalized;
    }

    public static IReadOnlyList<EvidenceMismatch> FindEvidenceMismatches(string json, JsonArray sources)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Analysis output is empty.");
        var ledger = sources.ToDictionary(x => x!["source_id"]!.GetValue<string>(), x => x!, StringComparer.Ordinal);
        var mismatches = new List<EvidenceMismatch>();
        Walk(root, "");
        return mismatches;

        void Walk(JsonNode? node, string path)
        {
            if (node is JsonObject obj)
            {
                foreach (var pair in obj)
                {
                    var childPath = path + "/" + pair.Key.Replace("~", "~0").Replace("/", "~1");
                    if (pair.Key == "evidence" && pair.Value is JsonArray evidence)
                    {
                        for (var i = 0; i < evidence.Count; i++)
                        {
                            if (evidence[i] is not JsonObject item || item["source_id"] is not JsonValue sid || !sid.TryGetValue<string>(out var id) || item["excerpt"] is not JsonValue ex || !ex.TryGetValue<string>(out var excerpt)) continue;
                            if (ledger.TryGetValue(id, out var source) && source["content"] is JsonValue contentNode && contentNode.TryGetValue<string>(out var content) && !EvidenceContains(content, excerpt))
                                mismatches.Add(new EvidenceMismatch($"{childPath}/{i}", id, excerpt, content));
                        }
                    }
                    else Walk(pair.Value, childPath);
                }
            }
            else if (node is JsonArray array)
                for (var i = 0; i < array.Count; i++) Walk(array[i], path + "/" + i);
        }
    }

    public static string ApplyEvidenceCorrections(string json, JsonArray sources, JsonArray corrections)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Analysis output is empty.");
        var ledger = sources.ToDictionary(x => x!["source_id"]!.GetValue<string>(), x => x!, StringComparer.Ordinal);
        var allowed = FindEvidenceMismatches(json, sources).ToDictionary(x => (x.Path, x.SourceId));
        foreach (var correction in corrections)
        {
            var path = correction!["path"]!.GetValue<string>();
            var sourceId = correction["source_id"]!.GetValue<string>();
            var excerpt = correction["excerpt"]!.GetValue<string>();
            if (!allowed.ContainsKey((path, sourceId)) || !ledger.TryGetValue(sourceId, out var source) || !EvidenceContains(source["content"]!.GetValue<string>(), excerpt)) continue;
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Replace("~1", "/").Replace("~0", "~")).ToArray();
            JsonNode? current = root;
            for (var i = 0; i < segments.Length && current is not null; i++) current = current is JsonArray array && int.TryParse(segments[i], out var index) ? array[index] : current[segments[i]];
            if (current is JsonObject obj && obj["source_id"]?.GetValue<string>() == sourceId) obj["excerpt"] = excerpt;
        }
        return root.ToJsonString();
    }

    private static EvidenceExcerptMismatchException Mismatch(string path, string sourceId, string excerpt, string source)
    {
        var mismatch = new EvidenceMismatch(path, sourceId, excerpt, source);
        return new EvidenceExcerptMismatchException($"Evidence excerpt does not match stored source text at {path} (source {sourceId}).", [mismatch]);
    }

    private static bool ContainsIndicatorText(string text, string indicator)
    {
        if (text.Contains(indicator, StringComparison.OrdinalIgnoreCase)) return true;
        var source = NormalizeIndicatorEvidenceText(IndicatorNormalization.Normalize(text));
        var value = NormalizeIndicatorEvidenceText(IndicatorNormalization.Normalize(indicator));
        return source.Contains(value, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeIndicatorEvidenceText(string text)
    {
        var normalized = text.Normalize(System.Text.NormalizationForm.FormKC)
            .Replace("\u0019", "'", StringComparison.Ordinal)
            .Replace("\u200B", "", StringComparison.Ordinal)
            .Replace("\u200C", "", StringComparison.Ordinal)
            .Replace("\u200D", "", StringComparison.Ordinal)
            .Replace("\uFEFF", "", StringComparison.Ordinal);
        return Regex.Replace(normalized, @"\s+", " ").Trim();
    }

    private static void CheckAssessment(JsonNode item)
    {
        if (item["confidence"]!.GetValue<string>() is not ("low" or "medium" or "high") || item["basis"]!.GetValue<string>() is not ("source_reported" or "inferred")) Fail("Invalid confidence or basis.");
    }

    private static void CheckIndicator(string type, string value)
    {
        bool valid = type switch
        {
            "ipv4" => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork,
            "ipv6" => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6,
            "md5" => Regex.IsMatch(value, "^[0-9a-fA-F]{32}$"),
            "sha1" => Regex.IsMatch(value, "^[0-9a-fA-F]{40}$"),
            "sha256" => Regex.IsMatch(value, "^[0-9a-fA-F]{64}$"),
            "domain" => Uri.CheckHostName(value) == UriHostNameType.Dns && value.Contains('.'),
            "url" => IsHttpUrlIndicator(value),
            "email" => System.Net.Mail.MailAddress.TryCreate(value, out var email) && email.Address == value,
            "file_name" or "file_path" or "registry_key" or "mutex" or "certificate_thumbprint" => !string.IsNullOrWhiteSpace(value),
            _ => false
        };
        if (!valid) Fail("Invalid or unsupported IOC type/value.");
    }

    private static bool IsHttpUrlIndicator(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var absolute))
        {
            if (absolute.Scheme is "http" or "https")
                return string.IsNullOrEmpty(absolute.UserInfo) && IsUrlHost(absolute.Host);
        }
        if (value.Contains("://", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(value)) return false;
        return Uri.TryCreate($"https://{value}", UriKind.Absolute, out var relative) &&
            relative.Scheme == "https" && string.IsNullOrEmpty(relative.UserInfo) && IsUrlHost(relative.Host);
    }

    private static bool IsUrlHost(string host) => Uri.CheckHostName(host) is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6;

    private static void CheckSchema(JsonNode? value, JsonObject schema, string path)
    {
        var types = schema["type"] is JsonArray a ? a.Select(x => x!.GetValue<string>()).ToArray() : new[] { schema["type"]!.GetValue<string>() };
        if (value is null) { if (!types.Contains("null")) Fail($"{path} cannot be null."); return; }
        if (types.Contains("object") && value is JsonObject obj)
        {
            var properties = schema["properties"]!.AsObject();
            foreach (var required in schema["required"]!.AsArray()) if (!obj.ContainsKey(required!.GetValue<string>())) Fail($"{path} is missing a required property.");
            foreach (var pair in obj)
            {
                if (!properties.TryGetPropertyValue(pair.Key, out var child)) Fail($"{path} contains an unknown property.");
                CheckSchema(pair.Value, child!.AsObject(), path + "." + pair.Key);
            }
        }
        else if (types.Contains("array") && value is JsonArray array)
        {
            if (array.Count > 500) Fail($"{path} contains too many items.");
            foreach (var item in array) CheckSchema(item, schema["items"]!.AsObject(), path + "[]");
        }
        else if (types.Contains("string") && value is JsonValue scalar && scalar.TryGetValue<string>(out var text))
        {
            if (text.Length > 10000) Fail($"{path} is too long.");
            if (schema["enum"] is JsonArray allowed && !allowed.Any(x => x!.GetValue<string>() == text)) Fail($"{path} has an invalid value.");
        }
        else Fail($"{path} has an invalid type.");
    }
    private static void Fail(string message) => throw new InvalidOperationException(message);
}
