using System.Text.Json;
using Json.Schema;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.EventEmitters;

namespace ThreatIntelAggro;

public static class DetectionYaml
{
    // XDRConverter CustomDetection.schema.json, commit 9c60aa8b653e89bf68ef4c318a92c1b62efe958b.
    private static readonly Lazy<JsonSchema> Schema = new(() =>
    {
        using var stream = typeof(DetectionYaml).Assembly.GetManifestResourceStream("ThreatIntelAggro.Schemas.XDRConverter.schema.json") ?? throw new InvalidOperationException("The XDRConverter schema is unavailable.");
        using var reader = new StreamReader(stream);
        return JsonSchema.FromText(reader.ReadToEnd());
    });
    private static readonly ISerializer Serializer = new SerializerBuilder().WithEventEmitter(next => new LiteralStrings(next)).Build();

    public static string Export(Dictionary<string, string?> detection)
    {
        var guid = detection.GetValueOrDefault("guid") ?? "";
        if (!Guid.TryParse(guid, out _)) throw new InvalidOperationException("This detection has no valid saved GUID; JSON and KQL exports remain available.");
        var tactic = detection.GetValueOrDefault("xdr_tactic") ?? "";
        var techniques = ParseTechniques(detection.GetValueOrDefault("xdr_techniques_json"));
        if (string.IsNullOrWhiteSpace(tactic) && !string.IsNullOrWhiteSpace(detection.GetValueOrDefault("yaml")))
            (tactic, techniques) = LegacyTactics(detection["yaml"]!);
        if (string.IsNullOrWhiteSpace(tactic)) throw new InvalidOperationException("This detection has no supported tactic; the XDRConverter schema requires one. JSON and KQL exports remain available.");
        var severity = (detection.GetValueOrDefault("severity") ?? "").ToLowerInvariant() switch { "informational" => "Informational", "low" => "Low", "medium" => "Medium", "high" => "High", _ => throw new InvalidOperationException("The detection has an invalid severity.") };
        var title = detection.GetValueOrDefault("alert_title") ?? "";
        var description = detection.GetValueOrDefault("description") ?? "";
        var query = detection.GetValueOrDefault("kql") ?? "";
        if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(query)) throw new InvalidOperationException("A title and KQL query are required for YAML export.");
        var tacticData = new Dictionary<string, object> { ["tactic"] = tactic, ["techniques"] = techniques };
        var document = new Dictionary<string, object>
        {
            ["guid"] = guid, ["ruleName"] = title, ["description"] = description, ["status"] = "disabled", ["frequency"] = "P1D",
            ["alertTitle"] = title, ["alertSeverity"] = severity, ["alertDescription"] = description,
            ["alertRecommendedAction"] = "Review the alert, validate the evidence, and follow the attached triage playbook.",
            ["tactics"] = new[] { tacticData }, ["queryText"] = query
        };
        var result = Schema.Value.Evaluate(JsonSerializer.SerializeToElement(document));
        if (!result.IsValid) throw new InvalidOperationException("The detection does not match the pinned XDRConverter schema. JSON and KQL exports remain available.");
        return Serializer.Serialize(document);
    }

    private static string[] ParseTechniques(string? json)
    {
        try { return string.IsNullOrWhiteSpace(json) ? [] : JsonSerializer.Deserialize<string[]>(json) ?? []; }
        catch (JsonException) { throw new InvalidOperationException("Saved detection techniques are invalid."); }
    }

    private static (string Tactic, string[] Techniques) LegacyTactics(string yaml)
    {
        if (yaml.Length > 100_000) throw new InvalidOperationException("Saved detection YAML exceeds the allowed size.");
        try
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(yaml));
            if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode root || !root.Children.TryGetValue(new YamlScalarNode("tactics"), out var node) || node is not YamlSequenceNode { Children.Count: > 0 } list || list.Children[0] is not YamlMappingNode tactic) return ("", []);
            var name = tactic.Children.TryGetValue(new YamlScalarNode("tactic"), out var tacticValue) ? (tacticValue as YamlScalarNode)?.Value ?? "" : "";
            var techniques = tactic.Children.TryGetValue(new YamlScalarNode("techniques"), out var ids) && ids is YamlSequenceNode sequence ? sequence.Children.OfType<YamlScalarNode>().Select(x => x.Value ?? "").ToArray() : [];
            return (name, techniques);
        }
        catch (YamlException) { throw new InvalidOperationException("The saved legacy YAML could not be read; JSON and KQL exports remain available."); }
    }

    private sealed class LiteralStrings(IEventEmitter next) : ChainedEventEmitter(next)
    {
        public override void Emit(ScalarEventInfo eventInfo, IEmitter emitter)
        {
            if (eventInfo.Source.Value is string value && value.Contains('\n')) eventInfo.Style = ScalarStyle.Literal;
            base.Emit(eventInfo, emitter);
        }
    }
}
