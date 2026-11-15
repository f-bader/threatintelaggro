using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public static class ArticleEvidenceValidator
{
    public static void Validate(string json, JsonArray sources, JsonObject schema)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Article output is empty.");
        CheckSchema(root, schema, "article");
        if (root["schema_version"]!.GetValue<string>() != "1.0") Fail("Unsupported article schema version.");
        var ledger = sources.ToDictionary(x => x!["source_id"]!.GetValue<string>(), x => x!, StringComparer.Ordinal);
        foreach (var reference in root["references"]!.AsArray())
        {
            var id = reference!["source_id"]!.GetValue<string>();
            if (!ledger.TryGetValue(id, out var source)) Fail("Reference names an unknown source.");
            foreach (var property in new[] { "url", "title", "kind", "inspection_status" })
                if (reference[property]!.GetValue<string>() != source![property]!.GetValue<string>()) Fail("Reference metadata does not match the source ledger.");
        }
        foreach (var item in root["iocs"]!.AsArray())
        {
            var ioc = item!;
            var type = ioc["type"]!.GetValue<string>();
            var value = ioc["value"]!.GetValue<string>();
            var normalized = ioc["normalized_value"]?.GetValue<string>() ?? value;
            if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || string.IsNullOrWhiteSpace(ioc["context"]!.GetValue<string>())) Fail("IOC value and context are required.");
            if (ioc["role"]!.GetValue<string>() is not ("malicious" or "suspicious" or "benign_context" or "unknown")) Fail("Invalid IOC role.");
            CheckAssessment(ioc);
            CheckIndicator(type, normalized);
            var evidence = ioc["evidence"]!.AsArray();
            if (evidence.Count == 0) Fail("IOC evidence is required.");
            var valueFound = false;
            foreach (var entry in evidence)
            {
                var id = entry!["source_id"]!.GetValue<string>();
                var excerpt = entry["excerpt"]!.GetValue<string>();
                if (!ledger.TryGetValue(id, out var source) || source!["inspection_status"]!.GetValue<string>() != "fetched") Fail("IOC cites an unknown or unfetched source.");
                var content = source!["content"]!.GetValue<string>();
                if (string.IsNullOrWhiteSpace(entry["locator"]!.GetValue<string>()) || string.IsNullOrWhiteSpace(excerpt) || excerpt.Length > 2000 || !content.Contains(excerpt, StringComparison.Ordinal)) Fail("IOC excerpt does not match the fetched source.");
                if (excerpt.Contains(value, StringComparison.OrdinalIgnoreCase) || excerpt.Contains(normalized, StringComparison.OrdinalIgnoreCase)) valueFound = true;
            }
            if (!valueFound) Fail("IOC value is absent from its cited sources.");
        }
        foreach (var field in new[] { "mitre_mappings", "industries", "threat_actors", "vendors", "products", "malware", "campaigns", "vulnerabilities", "targeted_countries" })
            foreach (var mapping in root[field]!.AsArray())
            {
                CheckAssessment(mapping!);
                var evidence = mapping!["evidence"]!.AsArray();
                if (evidence.Count == 0) Fail("Mapping evidence is required.");
                foreach (var item in evidence)
                {
                    var excerpt = item!.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(excerpt) || !ledger.Values.Any(source => source["inspection_status"]!.GetValue<string>() == "fetched" && source["content"]!.GetValue<string>().Contains(excerpt, StringComparison.Ordinal))) Fail("Mapping evidence does not match a fetched source.");
                }
            }
    }

    public static void ValidateDetection(string json, JsonArray sources, JsonObject schema)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Detection output is empty.");
        CheckSchema(root, schema, "detection");
        if (root["schema_version"]!.GetValue<string>() != "1.0") Fail("Unsupported detection schema version.");
        var detections = root["detections"]!.AsArray();
        if (root["outcome"]!.GetValue<string>() == "drafts_generated" && detections.Count == 0) Fail("Detection output contains no drafts.");
        foreach (var detection in detections)
        {
            if (detection!["severity"]!.GetValue<string>() is not ("informational" or "low" or "medium" or "high")) Fail("Invalid detection severity.");
            foreach (var mapping in detection["mitre_mappings"]!.AsArray())
            {
                CheckAssessment(mapping!);
                var evidence = mapping!["evidence"]!.AsArray();
                if (evidence.Count == 0) Fail("Detection mapping evidence is required.");
                foreach (var item in evidence)
                {
                    var excerpt = item!.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(excerpt) || !sources.Any(source => source!["inspection_status"]!.GetValue<string>() == "fetched" && source["content"]!.GetValue<string>().Contains(excerpt, StringComparison.Ordinal))) Fail("Detection mapping evidence does not match a fetched source.");
                }
            }
        }
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
            "url" => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" && string.IsNullOrEmpty(uri.UserInfo),
            "email" => System.Net.Mail.MailAddress.TryCreate(value, out var email) && email.Address == value,
            "file_name" or "file_path" or "registry_key" or "mutex" or "certificate_thumbprint" => !string.IsNullOrWhiteSpace(value),
            _ => false
        };
        if (!valid) Fail("Invalid or unsupported IOC type/value.");
    }

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
