using System.Text.Json;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public sealed record DetectionOverlap(long DetectionId, string Title, int Score, string Reason);

/// <summary>
/// Produces conservative review suggestions. It never merges or suppresses detections.
/// Indicator values are kept significant because otherwise unrelated IOC hunts look alike.
/// </summary>
public static partial class DetectionOverlapMatcher
{
    private static readonly HashSet<string> StopWords = new(StringComparer.Ordinal)
    {
        "a", "an", "and", "are", "as", "at", "be", "by", "can", "does", "for", "from", "in", "is", "it", "may", "of", "or", "possible", "reported", "the", "this", "to", "when", "with", "against", "use", "used", "that", "which", "their", "they", "will", "event", "query", "rule", "detect", "detects", "detection", "hunt", "process", "activity", "behavior", "observed"
    };

    public static IReadOnlyList<DetectionOverlap> FindCandidates(
        Dictionary<string, string?> detection,
        IEnumerable<Dictionary<string, string?>> others,
        int limit = 3)
        => FindCandidates(Read(detection), others.Select(Read), limit);

    public static IReadOnlyDictionary<long, IReadOnlyList<DetectionOverlap>> FindForQueue(
        IEnumerable<Dictionary<string, string?>> visible, IEnumerable<Dictionary<string, string?>> all)
    {
        var features = all.Select(Read).Where(item => item.Id > 0).ToDictionary(item => item.Id);
        return visible.Select(row => long.TryParse(row.GetValueOrDefault("id"), out var id) ? id : 0)
            .Where(features.ContainsKey)
            .ToDictionary(id => id, id => FindCandidates(features[id], features.Values, 3));
    }

    private static IReadOnlyList<DetectionOverlap> FindCandidates(
        DetectionFeatures current, IEnumerable<DetectionFeatures> others, int limit)
    {
        if (current.Id <= 0 || current.Tables.Count == 0 || current.FamilyId is not null) return [];
        var candidates = new Dictionary<string, DetectionOverlap>(StringComparer.Ordinal);
        foreach (var candidate in others)
        {
            if (candidate.Id <= 0 || candidate.Id == current.Id || candidate.Tables.Count == 0) continue;
            if (!current.Tables.Overlaps(candidate.Tables) || HasConflictingIndicators(current.Kql, candidate.Kql)) continue;

            var titleScore = OverlapCoefficient(current.TitleTokens, candidate.TitleTokens);
            var descriptionScore = OverlapCoefficient(current.DescriptionTokens, candidate.DescriptionTokens);
            var behaviorScore = OverlapCoefficient(current.BehaviorTokens, candidate.BehaviorTokens);
            var score = Math.Max(titleScore, Math.Max(descriptionScore, behaviorScore));
            var strongSignalCount = new[] { titleScore, descriptionScore, behaviorScore }.Count(x => x >= 0.35);
            if (score < 0.55 && !(score >= 0.40 && strongSignalCount >= 2)) continue;

            var reason = titleScore >= descriptionScore && titleScore >= behaviorScore
                ? "Similar detection titles and shared telemetry"
                : behaviorScore >= descriptionScore
                    ? "Similar behavior descriptions and shared telemetry"
                    : "Similar descriptions and shared telemetry";
            var suggestion = new DetectionOverlap(candidate.Id, candidate.Title, (int)Math.Round(score * 100), reason);
            var key = candidate.FamilyId ?? $"detection:{candidate.Id}";
            if (!candidates.TryGetValue(key, out var existing) || suggestion.Score > existing.Score)
                candidates[key] = suggestion;
        }
        return candidates.Values.OrderByDescending(x => x.Score).ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase).Take(Math.Clamp(limit, 1, 10)).ToArray();
    }

    private static bool HasConflictingIndicators(string left, string right)
    {
        var a = IndicatorValues(left);
        var b = IndicatorValues(right);
        if (a.Count == 0 || b.Count == 0) return false;
        var leftValues = a.Values.SelectMany(x => x).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rightValues = b.Values.SelectMany(x => x).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return leftValues.Count > 0 && rightValues.Count > 0 && !leftValues.Overlaps(rightValues);
    }

    private static Dictionary<string, HashSet<string>> IndicatorValues(string kql)
    {
        var result = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in IndicatorPredicate().Matches(kql))
        {
            var field = match.Groups[1].Value;
            if (!result.TryGetValue(field, out var values)) result[field] = values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match literal in QuotedLiteral().Matches(match.Groups["values"].Value))
                values.Add(literal.Groups[1].Value.Trim().TrimEnd('.'));
        }
        return result;
    }

    private static DetectionFeatures Read(Dictionary<string, string?> row)
    {
        var behaviorText = "";
        try
        {
            using var json = JsonDocument.Parse(row.GetValueOrDefault("behaviors_json") ?? "[]");
            if (json.RootElement.ValueKind == JsonValueKind.Array)
                behaviorText = string.Join(' ', json.RootElement.EnumerateArray()
                    .Where(x => x.ValueKind == JsonValueKind.Object && x.TryGetProperty("description", out _))
                    .Select(x => x.GetProperty("description").GetString() ?? ""));
        }
        catch (JsonException) { }

        var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var json = JsonDocument.Parse(row.GetValueOrDefault("telemetry_json") ?? "{}");
            if (json.RootElement.ValueKind == JsonValueKind.Object && json.RootElement.TryGetProperty("tables", out var tableArray) && tableArray.ValueKind == JsonValueKind.Array)
                foreach (var table in tableArray.EnumerateArray())
                    if (table.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(table.GetString())) tables.Add(table.GetString()!.Trim());
        }
        catch (JsonException) { }

        var title = row.GetValueOrDefault("alert_title") ?? "";
        return new DetectionFeatures(
            long.TryParse(row.GetValueOrDefault("id"), out var id) ? id : 0,
            title,
            row.GetValueOrDefault("family_id"),
            WordSet(title),
            WordSet(row.GetValueOrDefault("description") ?? ""),
            WordSet(behaviorText),
            tables,
            row.GetValueOrDefault("kql") ?? "");
    }

    private static HashSet<string> WordSet(string text) => Words().Matches(text.ToLowerInvariant()).Select(x => x.Value)
        .Where(x => x.Length > 2 && !StopWords.Contains(x)).ToHashSet(StringComparer.Ordinal);

    private static double OverlapCoefficient(HashSet<string> a, HashSet<string> b) =>
        a.Count == 0 || b.Count == 0 ? 0 : (double)a.Intersect(b).Count() / Math.Min(a.Count, b.Count);

    private sealed record DetectionFeatures(long Id, string Title, string? FamilyId, HashSet<string> TitleTokens,
        HashSet<string> DescriptionTokens, HashSet<string> BehaviorTokens, HashSet<string> Tables, string Kql);

    [GeneratedRegex("\\b(SHA1|SHA256|SHA512|MD5|RemoteIP|RemoteUrl|RemoteDomain)\\s*(?:=~|==|contains|in~?|has)\\s*(?<values>\\((?:[^()]|\\([^()]*\\))*\\)|\"(?:[^\"\\\\]|\\\\.)*\")", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IndicatorPredicate();

    [GeneratedRegex("\"((?:[^\"\\\\]|\\\\.)*)\"", RegexOptions.CultureInvariant)]
    private static partial Regex QuotedLiteral();

    [GeneratedRegex("[a-z0-9]+", RegexOptions.CultureInvariant)]
    private static partial Regex Words();
}
