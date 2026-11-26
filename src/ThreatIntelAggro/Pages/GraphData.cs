using System.Text.Json;

namespace ThreatIntelAggro.Pages;

public sealed record ThreatGraphQuery(
    string Scope,
    string? Search,
    string? Category,
    string? Source,
    string? IocStatus,
    int Days,
    bool IncludeCoMentions,
    IReadOnlySet<string> Types,
    bool TypesSpecified = false);

public sealed record ThreatGraphData(
    IReadOnlyList<ThreatGraphNode> Nodes,
    IReadOnlyList<ThreatGraphEdge> Edges,
    string Scope,
    int ArticleCount)
{
    public static ThreatGraphData Empty(string scope = "") => new([], [], scope, 0);
}

public sealed class ThreatGraphNode
{
    public required string Id { get; init; }
    public required string Type { get; init; }
    public required string TypeLabel { get; init; }
    public required string Label { get; init; }
    public string Details { get; init; } = "";
    public string? Category { get; init; }
    public string? Source { get; init; }
    public string? IocStatus { get; init; }
    public string? Url { get; init; }
    public long? ArticleId { get; init; }
}

public sealed class ThreatGraphEdge
{
    public required string Id { get; init; }
    public required string Source { get; init; }
    public required string Target { get; init; }
    public required string Label { get; init; }
    public required string Kind { get; init; }
    public required string EvidenceTitle { get; init; }
    public required string EvidenceUrl { get; init; }
    public int EvidenceCount { get; set; } = 1;
}

public static class ThreatGraphBuilder
{
    private static readonly (string Key, string Label, string Field)[] ArticleEntityTypes =
    [
        ("vendor", "Vendor", "vendors"),
        ("product", "Product", "products"),
        ("industry", "Industry", "industries"),
        ("actor", "Threat actor", "threat_actors"),
        ("malware", "Malware", "malware"),
        ("campaign", "Campaign", "campaigns"),
        ("vulnerability", "Vulnerability", "vulnerabilities"),
        ("country", "Targeted country", "targeted_countries"),
        ("technique", "MITRE technique", "mitre_mappings")
    ];

    public static ThreatGraphData Build(AppDatabase database, ThreatGraphQuery query)
    {
        var scope = NormalizeScope(query.Scope);
        if (scope.Length == 0) return ThreatGraphData.Empty();

        var category = scope == "recent" && string.IsNullOrWhiteSpace(query.Category)
            ? ArticleCategories.TimeCritical
            : query.Category?.Trim();
        var source = query.Source?.Trim();
        var status = NormalizeIocStatus(query.IocStatus);
        var cutoff = query.Days > 0 ? DateTimeOffset.UtcNow.AddDays(-query.Days).ToString("O") : null;
        var clauses = new List<string> { "a.ai_status='analyzed'", "a.evidence_verified=1", "a.analysis_json IS NOT NULL" };
        var args = new List<object?>();
        if (!string.IsNullOrWhiteSpace(category)) { clauses.Add("a.category=? COLLATE NOCASE"); args.Add(category); }
        if (!string.IsNullOrWhiteSpace(source)) { clauses.Add("a.feed_title=? COLLATE NOCASE"); args.Add(source); }
        if (cutoff is not null) { clauses.Add("COALESCE(a.published_utc,a.first_seen_utc)>=?"); args.Add(cutoff); }

        var articles = database.Query($"SELECT a.id,a.feed_title,a.title,a.url,a.summary,a.published_utc,a.first_seen_utc,a.analysis_json,a.category FROM articles a WHERE {string.Join(" AND ", clauses)} ORDER BY COALESCE(a.published_utc,a.first_seen_utc) DESC,a.id DESC", args.ToArray());
        var nodes = new Dictionary<string, ThreatGraphNode>(StringComparer.OrdinalIgnoreCase);
        var edges = new Dictionary<string, ThreatGraphEdge>(StringComparer.OrdinalIgnoreCase);
        var perArticleEntityNodes = new Dictionary<long, HashSet<string>>();
        var articleNodeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var articleRowsById = articles.ToDictionary(row => ParseLong(row.GetValueOrDefault("id")), row => row);
        var roleOverrides = ReadRoleOverrides(database, articleRowsById.Keys);
        var articleIdsWithStatusMatch = new HashSet<long>();

        foreach (var row in articles)
        {
            var id = ParseLong(row.GetValueOrDefault("id"));
            if (id <= 0 || !TryParse(row.GetValueOrDefault("analysis_json"), out var document)) continue;
            using (document)
            {
                var root = document.RootElement;
                var iocs = ReadIocs(root, id, roleOverrides);
                if (status is not null && !iocs.Any(ioc => ioc.Status == status)) continue;

                var title = NonEmpty(row.GetValueOrDefault("title"), "Untitled report");
                var url = row.GetValueOrDefault("url") ?? "";
                var feedTitle = NonEmpty(row.GetValueOrDefault("feed_title"), "Unknown source");
                var articleCategory = NonEmpty(row.GetValueOrDefault("category"), ArticleCategories.ExistingResearch);
                var articleNodeId = Key("article", id.ToString(System.Globalization.CultureInfo.InvariantCulture));
                articleNodeIds.Add(articleNodeId);
                AddNode(nodes, new ThreatGraphNode
                {
                    Id = articleNodeId, Type = "article", TypeLabel = "Article", Label = title,
                    Details = NonEmpty(ReadText(root, "summary", "overview"), row.GetValueOrDefault("summary") ?? ""),
                    Category = articleCategory, Source = feedTitle, Url = url, ArticleId = id
                });

                var sourceId = Key("source", feedTitle);
                AddNode(nodes, new ThreatGraphNode { Id = sourceId, Type = "source", TypeLabel = "Source", Label = feedTitle, Details = $"Source feed for {title}" });
                AddEdge(edges, sourceId, articleNodeId, "publishes", "direct", title, url);

                var entityNodeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var definition in ArticleEntityTypes)
                {
                    if (!TryGetArray(root, definition.Field, out var mappings)) continue;
                    foreach (var mapping in mappings.EnumerateArray())
                    {
                        var name = ReadEntityName(mapping);
                        if (name.Length == 0) continue;
                        var detail = ReadText(mapping, "rationale", "description", "context", "affected_role");
                        var names = definition.Key == "industry" && name.Contains(',')
                            ? name.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(value => value.StartsWith("and ", StringComparison.OrdinalIgnoreCase) ? value[4..].Trim() : value).Where(value => value.Length > 0)
                            : [name];
                        foreach (var entityName in names)
                        {
                            var nodeId = Key(definition.Key, entityName);
                            AddNode(nodes, new ThreatGraphNode
                            {
                                Id = nodeId, Type = definition.Key, TypeLabel = definition.Label,
                                Label = entityName, Details = detail
                            });
                            AddEdge(edges, articleNodeId, nodeId, $"mentions {definition.Label.ToLowerInvariant()}", "direct", title, url);
                            entityNodeIds.Add(nodeId);

                            if (definition.Key == "product" && TryGetString(mapping, "vendor_name", out var vendorName) && vendorName.Length > 0)
                            {
                                var vendorId = Key("vendor", vendorName);
                                AddNode(nodes, new ThreatGraphNode { Id = vendorId, Type = "vendor", TypeLabel = "Vendor", Label = vendorName });
                                AddEdge(edges, nodeId, vendorId, "associated vendor", "direct", title, url);
                                entityNodeIds.Add(vendorId);
                            }
                        }
                    }
                }

                foreach (var ioc in iocs)
                {
                    if (status is not null && ioc.Status != status) continue;
                    var nodeId = Key("ioc", $"{ioc.Type}|{ioc.Value}");
                    AddNode(nodes, new ThreatGraphNode
                    {
                        Id = nodeId, Type = "ioc", TypeLabel = $"IOC · {ioc.Type}", Label = ioc.Value,
                        Details = ioc.Context, IocStatus = ioc.Status, Category = articleCategory,
                        Source = feedTitle, ArticleId = id, Url = url
                    });
                    AddEdge(edges, articleNodeId, nodeId, $"contains IOC · {ioc.Status}", "direct", title, url);
                    entityNodeIds.Add(nodeId);
                }

                perArticleEntityNodes[id] = entityNodeIds;
                articleIdsWithStatusMatch.Add(id);
            }
        }

        if (status is not null)
        {
            var retainedArticleIds = articleIdsWithStatusMatch;
            var removeIds = nodes.Values.Where(node => node.ArticleId.HasValue && !retainedArticleIds.Contains(node.ArticleId.Value)).Select(node => node.Id).ToArray();
            foreach (var nodeId in removeIds) nodes.Remove(nodeId);
            var retainedNodeIds = nodes.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var edgeKey in edges.Where(pair => !retainedNodeIds.Contains(pair.Value.Source) || !retainedNodeIds.Contains(pair.Value.Target)).Select(pair => pair.Key).ToArray()) edges.Remove(edgeKey);
        }

        AddDetectionNodes(database, articleNodeIds, nodes, edges);

        if (query.IncludeCoMentions)
            AddCoMentionEdges(articleIdsWithStatusMatch, perArticleEntityNodes, articleRowsById, edges);

        var matchedSeedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (scope == "search" && !string.IsNullOrWhiteSpace(query.Search))
        {
            var needle = query.Search.Trim();
            var exactMatches = nodes.Values.Where(node => node.Label.Equals(needle, StringComparison.OrdinalIgnoreCase)).Select(node => node.Id).ToArray();
            if (exactMatches.Length > 0) matchedSeedIds.UnionWith(exactMatches);
            else foreach (var node in nodes.Values)
                if (node.Label.Contains(needle, StringComparison.OrdinalIgnoreCase)) matchedSeedIds.Add(node.Id);

            if (matchedSeedIds.Count == 0) return ThreatGraphData.Empty("search");
            var oneHopNodeIds = new HashSet<string>(matchedSeedIds, StringComparer.OrdinalIgnoreCase);
            foreach (var edge in edges.Values)
            {
                if (matchedSeedIds.Contains(edge.Source)) oneHopNodeIds.Add(edge.Target);
                if (matchedSeedIds.Contains(edge.Target)) oneHopNodeIds.Add(edge.Source);
            }
            nodes = nodes.Where(pair => oneHopNodeIds.Contains(pair.Key)).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
            edges = edges.Where(pair => matchedSeedIds.Contains(pair.Value.Source) || matchedSeedIds.Contains(pair.Value.Target))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        }
        else if (scope == "search") return ThreatGraphData.Empty("search");

        if (query.TypesSpecified)
        {
            var visibleIds = nodes.Values.Where(node => query.Types.Contains(node.Type)).Select(node => node.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            nodes = nodes.Where(pair => visibleIds.Contains(pair.Key)).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
            edges = edges.Where(pair => visibleIds.Contains(pair.Value.Source) && visibleIds.Contains(pair.Value.Target))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        }

        return new ThreatGraphData(
            nodes.Values.OrderBy(node => TypeOrder(node.Type)).ThenBy(node => node.Label, StringComparer.OrdinalIgnoreCase).ToArray(),
            edges.Values.OrderBy(edge => edge.Source, StringComparer.OrdinalIgnoreCase).ThenBy(edge => edge.Target, StringComparer.OrdinalIgnoreCase).ThenBy(edge => edge.Label, StringComparer.OrdinalIgnoreCase).ToArray(),
            scope,
            articleNodeIds.Count);
    }

    private static void AddDetectionNodes(AppDatabase database, HashSet<string> articleNodeIds, Dictionary<string, ThreatGraphNode> nodes, Dictionary<string, ThreatGraphEdge> edges)
    {
        var articleIdByNode = articleNodeIds.ToDictionary(nodeId => nodeId, nodeId => long.TryParse(nodeId.AsSpan("article:".Length), out var value) ? value : 0, StringComparer.OrdinalIgnoreCase);
        var articleRows = articleIdByNode.Where(pair => pair.Value > 0).ToDictionary(pair => pair.Value, pair => pair.Key);
        if (articleRows.Count == 0) return;

        var detections = database.Query("SELECT d.id,d.article_id,d.alert_title,d.description,d.mitre_json,d.playbook_json,a.title AS article_title,a.url AS article_url FROM detections d JOIN articles a ON a.id=d.article_id");
        foreach (var detection in detections)
        {
            if (!long.TryParse(detection.GetValueOrDefault("id"), out var detectionId) || !long.TryParse(detection.GetValueOrDefault("article_id"), out var articleId) || !articleRows.TryGetValue(articleId, out var articleNodeId)) continue;
            var articleTitle = detection.GetValueOrDefault("article_title") ?? "Source article";
            var articleUrl = detection.GetValueOrDefault("article_url") ?? "";
            var title = NonEmpty(detection.GetValueOrDefault("alert_title"), "Detection idea");
            var detectionNodeId = Key("detection", detectionId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AddNode(nodes, new ThreatGraphNode
            {
                Id = detectionNodeId, Type = "detection", TypeLabel = "Detection", Label = title,
                Details = detection.GetValueOrDefault("description") ?? "", ArticleId = articleId, Url = articleUrl
            });
            AddEdge(edges, articleNodeId, detectionNodeId, "generated detection", "direct", articleTitle, articleUrl);

            foreach (var mapping in ReadJsonArray(detection.GetValueOrDefault("mitre_json")))
            {
                var technique = ReadEntityName(mapping);
                if (technique.Length == 0) continue;
                var techniqueId = Key("technique", technique);
                AddNode(nodes, new ThreatGraphNode { Id = techniqueId, Type = "technique", TypeLabel = "MITRE technique", Label = technique });
                AddEdge(edges, detectionNodeId, techniqueId, "maps to", "direct", articleTitle, articleUrl);
            }

            foreach (var response in ReadResponseOptions(detection.GetValueOrDefault("playbook_json")))
            {
                var recommendationId = Key("recommendation", response);
                AddNode(nodes, new ThreatGraphNode { Id = recommendationId, Type = "recommendation", TypeLabel = "Recommendation", Label = response, Details = "Detection playbook response option" });
                AddEdge(edges, detectionNodeId, recommendationId, "recommends", "direct", articleTitle, articleUrl);
            }
        }
    }

    private static void AddCoMentionEdges(HashSet<long> includedArticleIds, Dictionary<long, HashSet<string>> perArticleEntityNodes, Dictionary<long, Dictionary<string, string?>> articleRowsById, Dictionary<string, ThreatGraphEdge> edges)
    {
        foreach (var (articleId, ids) in perArticleEntityNodes)
        {
            if (!includedArticleIds.Contains(articleId) || ids.Count < 2 || !articleRowsById.TryGetValue(articleId, out var article)) continue;
            var ordered = ids.Order(StringComparer.OrdinalIgnoreCase).ToArray();
            for (var left = 0; left < ordered.Length; left++)
            for (var right = left + 1; right < ordered.Length; right++)
                AddEdge(edges, ordered[left], ordered[right], "co-mentioned in article", "co-mention", article.GetValueOrDefault("title") ?? "Source article", article.GetValueOrDefault("url") ?? "");
        }
    }

    private static Dictionary<string, string> ReadRoleOverrides(AppDatabase database, IEnumerable<long> articleIds)
    {
        var ids = articleIds.ToHashSet();
        if (ids.Count == 0) return new(StringComparer.OrdinalIgnoreCase);
        var overrides = database.Query("SELECT article_id,ioc_type,ioc_value,role FROM ioc_role_overrides")
            .Where(row => ids.Contains(ParseLong(row.GetValueOrDefault("article_id"))));
        return overrides.ToDictionary(row => IocKey(ParseLong(row.GetValueOrDefault("article_id")), row.GetValueOrDefault("ioc_type") ?? "", row.GetValueOrDefault("ioc_value") ?? ""), row => row.GetValueOrDefault("role") ?? "unknown", StringComparer.OrdinalIgnoreCase);
    }

    private static List<GraphIoc> ReadIocs(JsonElement root, long articleId, IReadOnlyDictionary<string, string> overrides)
    {
        if (!TryGetArray(root, "iocs", out var array)) return [];
        var result = new List<GraphIoc>();
        foreach (var element in array.EnumerateArray())
        {
            var type = ReadText(element, "type");
            var value = ReadText(element, "value");
            if (type.Length == 0 || value.Length == 0) continue;
            var originalRole = NonEmpty(ReadText(element, "role"), "unknown");
            var status = overrides.GetValueOrDefault(IocKey(articleId, type, value), originalRole);
            result.Add(new GraphIoc(type, value, status, ReadText(element, "context")));
        }
        return result;
    }

    private static IEnumerable<JsonElement> ReadJsonArray(string? json)
    {
        if (!TryParse(json, out var document)) return [];
        using (document) return document.RootElement.ValueKind == JsonValueKind.Array ? document.RootElement.EnumerateArray().Select(item => item.Clone()).ToArray() : [];
    }

    private static IEnumerable<string> ReadResponseOptions(string? json)
    {
        if (!TryParse(json, out var document)) return [];
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("response_options", out var array) || array.ValueKind != JsonValueKind.Array) return [];
            return array.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()?.Trim() ?? "").Where(value => value.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    private static void AddNode(Dictionary<string, ThreatGraphNode> nodes, ThreatGraphNode node)
    {
        if (!nodes.TryGetValue(node.Id, out var existing)) nodes[node.Id] = node;
    }

    private static void AddEdge(Dictionary<string, ThreatGraphEdge> edges, string source, string target, string label, string kind, string evidenceTitle, string evidenceUrl)
    {
        var key = $"{source}\u001f{target}\u001f{label}";
        if (edges.TryGetValue(key, out var existing)) existing.EvidenceCount++;
        else edges[key] = new ThreatGraphEdge { Id = key, Source = source, Target = target, Label = label, Kind = kind, EvidenceTitle = evidenceTitle, EvidenceUrl = evidenceUrl };
    }

    private static string Key(string type, string value) => $"{type}:{value.Trim().ToUpperInvariant()}";
    private static string IocKey(long articleId, string type, string value) => $"{articleId}\u001f{type}\u001f{value}";
    private static string NormalizeScope(string? scope) => scope?.Trim().ToLowerInvariant() switch { "recent" => "recent", "all" => "all", "search" => "search", _ => "" };
    private static string? NormalizeIocStatus(string? status) => status?.Trim().ToLowerInvariant() switch { "malicious" or "suspicious" or "benign_context" or "unknown" => status.Trim().ToLowerInvariant(), _ => null };
    private static int TypeOrder(string type) => Array.IndexOf(new[] { "source", "article", "vendor", "product", "industry", "actor", "malware", "campaign", "vulnerability", "country", "ioc", "technique", "detection", "recommendation" }, type);
    private static long ParseLong(string? value) => long.TryParse(value, out var result) ? result : 0;
    private static string NonEmpty(string? value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
    private static bool TryParse(string? json, out JsonDocument document)
    {
        try { document = JsonDocument.Parse(json ?? ""); return true; }
        catch (JsonException) { document = null!; return false; }
    }
    private static bool TryGetArray(JsonElement root, string property, out JsonElement array)
    {
        array = default;
        return root.ValueKind == JsonValueKind.Object && root.TryGetProperty(property, out array) && array.ValueKind == JsonValueKind.Array;
    }
    private static bool TryGetString(JsonElement element, string property, out string value)
    {
        value = element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var raw) && raw.ValueKind == JsonValueKind.String ? raw.GetString()?.Trim() ?? "" : "";
        return value.Length > 0;
    }
    private static string ReadEntityName(JsonElement item) => NonEmpty(ReadText(item, "name"), NonEmpty(ReadText(item, "value"), ReadText(item, "id")));
    private static string ReadText(JsonElement element, params string[] paths)
    {
        foreach (var path in paths)
        {
            var current = element;
            var found = true;
            foreach (var part in path.Split('.'))
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(part, out current)) { found = false; break; }
            }
            if (found && current.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(current.GetString())) return current.GetString()!.Trim();
        }
        return "";
    }
    private static string ReadText(JsonElement element, string parent, string child) => ReadText(element, $"{parent}.{child}");
    private sealed record GraphIoc(string Type, string Value, string Status, string Context);
}
