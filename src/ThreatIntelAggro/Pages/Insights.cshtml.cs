using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ThreatIntelAggro.Pages;

public sealed class InsightsModel(AppDatabase database) : PageModel
{
    private static readonly (string Key, string Label, string Field)[] CategoryDefinitions =
    [
        ("vendors", "VENDORS", "vendors"),
        ("industries", "INDUSTRIES", "industries"),
        ("actors", "THREAT ACTORS", "threat_actors")
    ];

    public int Days { get; private set; } = 30;
    public int ArticleCount { get; private set; }
    public IReadOnlyList<InsightCategory> Categories { get; private set; } = [];
    public IReadOnlyList<ActivityBucket> Activity { get; private set; } = [];
    public IReadOnlyList<InsightEntity> RisingEntities { get; private set; } = [];
    public IReadOnlyList<InsightEntity> CoMentionEntities { get; private set; } = [];
    public IReadOnlyList<CoMentionRow> CoMentionRows { get; private set; } = [];
    public IReadOnlyDictionary<string, string[]> RelatedEntityKeys { get; private set; } = new Dictionary<string, string[]>();
    public int CoMentionMaximum { get; private set; }
    public string ActivityLinePoints => string.Join(" ", Activity.Select(bucket => FormattableString.Invariant($"{bucket.X:0.##},{bucket.Y:0.##}")));
    public string ActivityAreaPoints => $"38,132 {ActivityLinePoints} 496,132";
    public string ActivityDateLabelMarkup(ActivityBucket bucket)
    {
        var hiddenClass = bucket.ShowLabel ? "" : " insight-activity-date-hidden";
        return FormattableString.Invariant($"<text class=\"insight-activity-date-label{hiddenClass}\" x=\"{bucket.X:0.##}\" y=\"157\">{HtmlEncoder.Default.Encode(bucket.Label)}</text>");
    }
    public string PeriodLabel => Days == 1 ? "LAST 24 HOURS" : $"LAST {Days} DAYS";

    public void OnGet(int days = 30)
    {
        Days = days is 7 or 30 or 90 or 365 ? days : 30;
        var now = DateTimeOffset.UtcNow;
        var currentStart = now.AddDays(-Days);
        var previousStart = currentStart.AddDays(-Days);
        var articles = database.Query(
            "SELECT id,title,COALESCE(published_utc,first_seen_utc) AS observed_utc,analysis_json FROM articles WHERE ai_status='analyzed' AND analysis_json IS NOT NULL AND COALESCE(published_utc,first_seen_utc) >= ? ORDER BY COALESCE(published_utc,first_seen_utc) DESC",
            previousStart.ToString("O"));

        var entities = CategoryDefinitions.ToDictionary(
            definition => definition.Key,
            _ => new Dictionary<string, MutableEntity>(StringComparer.OrdinalIgnoreCase),
            StringComparer.Ordinal);
        var activityCounts = new int[12];
        var articleIdsWithEntities = new HashSet<long>();
        var coMentionCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var article in articles)
        {
            if (!long.TryParse(article.GetValueOrDefault("id"), out var articleId) ||
                !DateTimeOffset.TryParse(article.GetValueOrDefault("observed_utc"), out var observedUtc) ||
                string.IsNullOrWhiteSpace(article.GetValueOrDefault("analysis_json"))) continue;

            try
            {
                using var document = JsonDocument.Parse(article["analysis_json"]!);
                var root = document.RootElement;
                var isCurrent = observedUtc >= currentStart;
                var hasEntities = false;
                var articleEntityIds = new HashSet<string>(StringComparer.Ordinal);
                foreach (var definition in CategoryDefinitions)
                {
                    foreach (var name in IocIndex.Values(root, definition.Field))
                    {
                        hasEntities = true;
                        if (!entities[definition.Key].TryGetValue(name, out var aggregate))
                        {
                            aggregate = new MutableEntity(name, definition.Key, definition.Label);
                            entities[definition.Key].Add(name, aggregate);
                        }
                        if (isCurrent)
                        {
                            aggregate.CurrentArticleIds.Add(articleId);
                            articleEntityIds.Add(EntityId(definition.Key, aggregate.Name));
                        }
                        else aggregate.PreviousArticleIds.Add(articleId);
                    }
                }

                if (isCurrent && hasEntities)
                {
                    articleIdsWithEntities.Add(articleId);
                    var elapsedDays = (observedUtc - currentStart).TotalDays;
                    var bucket = Math.Clamp((int)(elapsedDays * activityCounts.Length / Days), 0, activityCounts.Length - 1);
                    activityCounts[bucket]++;
                    var articleEntities = articleEntityIds.Order(StringComparer.Ordinal).ToArray();
                    for (var left = 0; left < articleEntities.Length; left++)
                    for (var right = left + 1; right < articleEntities.Length; right++)
                    {
                        var key = PairKey(articleEntities[left], articleEntities[right]);
                        coMentionCounts[key] = coMentionCounts.GetValueOrDefault(key) + 1;
                    }
                }
            }
            catch (JsonException) { }
        }

        ArticleCount = articleIdsWithEntities.Count;
        Categories = CategoryDefinitions.Select(definition =>
        {
            var categoryEntities = entities[definition.Key].Values
                .Where(entity => entity.CurrentArticleIds.Count > 0)
                .Select(entity => entity.ToInsightEntity())
                .OrderByDescending(entity => entity.ArticleCount)
                .ThenBy(entity => entity.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new InsightCategory(definition.Key, definition.Label, categoryEntities.Length, categoryEntities);
        }).ToArray();

        var bucketDays = Math.Max(1d, (double)Days / activityCounts.Length);
        var maxActivity = activityCounts.Max();
        Activity = activityCounts.Select((count, index) => new ActivityBucket(
            currentStart.AddDays(index * bucketDays).ToLocalTime().ToString("dd MMM"), count,
            38 + index * 458d / (activityCounts.Length - 1),
            maxActivity == 0 ? 132 : 132 - count * 92d / maxActivity,
            index % 2 == 0 || index == activityCounts.Length - 1)).ToArray();

        RisingEntities = entities.Values.SelectMany(category => category.Values)
            .Select(entity => entity.ToInsightEntity())
            .Where(entity => entity.ArticleCount > entity.PreviousArticleCount)
            .OrderByDescending(entity => entity.Change)
            .ThenByDescending(entity => entity.ArticleCount)
            .ThenBy(entity => entity.Name, StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();

        CoMentionEntities = Categories.SelectMany(category => category.Entities.Take(4)).ToArray();
        CoMentionRows = CoMentionEntities.Select(row => new CoMentionRow(row, CoMentionEntities.Select(column =>
        {
            if (EntityId(row.CategoryKey, row.Name) == EntityId(column.CategoryKey, column.Name))
                return new CoMentionCell(column, null);
            return new CoMentionCell(column, coMentionCounts.GetValueOrDefault(PairKey(
                EntityId(row.CategoryKey, row.Name), EntityId(column.CategoryKey, column.Name))));
        }).ToArray())).ToArray();
        CoMentionMaximum = CoMentionRows.SelectMany(row => row.Cells)
            .Where(cell => cell.ArticleCount.HasValue)
            .Select(cell => cell.ArticleCount!.Value)
            .DefaultIfEmpty(0)
            .Max();

        var relatedEntities = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var pair in coMentionCounts.Where(pair => pair.Value > 0))
        {
            var keys = pair.Key.Split('\u001e');
            if (keys.Length != 2) continue;
            if (!relatedEntities.TryGetValue(keys[0], out var left)) relatedEntities[keys[0]] = left = new(StringComparer.Ordinal);
            if (!relatedEntities.TryGetValue(keys[1], out var right)) relatedEntities[keys[1]] = right = new(StringComparer.Ordinal);
            left.Add(keys[1]);
            right.Add(keys[0]);
        }
        RelatedEntityKeys = relatedEntities.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.Ordinal);
    }

    public string EntityKey(InsightEntity entity) => EntityId(entity.CategoryKey, entity.Name);
    public string RelatedEntityKeysJson(InsightEntity entity) =>
        JsonSerializer.Serialize(RelatedEntityKeys.GetValueOrDefault(EntityKey(entity), []));

    public IReadOnlyList<InsightTreemapTile> TreemapTiles() =>
        LayoutTreemap(Categories.SelectMany(category => category.Entities)
            .OrderByDescending(entity => entity.ArticleCount)
            .ThenBy(entity => entity.CategoryKey, StringComparer.Ordinal)
            .ThenBy(entity => entity.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray(), 0, 0, 100, 100);

    private static IReadOnlyList<InsightTreemapTile> LayoutTreemap(InsightEntity[] entities, double left, double top, double width, double height)
    {
        if (entities.Length == 0) return [];
        if (entities.Length == 1) return [new InsightTreemapTile(entities[0], left, top, width, height)];

        var total = entities.Sum(entity => Math.Max(1, entity.ArticleCount));
        var running = 0;
        var splitIndex = 1;
        var closestDistance = double.MaxValue;
        for (var index = 1; index < entities.Length; index++)
        {
            running += Math.Max(1, entities[index - 1].ArticleCount);
            var distance = Math.Abs(total / 2d - running);
            if (distance >= closestDistance) continue;
            closestDistance = distance;
            splitIndex = index;
        }

        var first = entities[..splitIndex];
        var second = entities[splitIndex..];
        var firstWeight = first.Sum(entity => Math.Max(1, entity.ArticleCount));
        var firstShare = (double)firstWeight / total;
        if (width >= height)
        {
            var firstWidth = width * firstShare;
            return LayoutTreemap(first, left, top, firstWidth, height)
                .Concat(LayoutTreemap(second, left + firstWidth, top, width - firstWidth, height)).ToArray();
        }

        var firstHeight = height * firstShare;
        return LayoutTreemap(first, left, top, width, firstHeight)
            .Concat(LayoutTreemap(second, left, top + firstHeight, width, height - firstHeight)).ToArray();
    }

    public string CoMentionOpacity(int? count) => count is null || CoMentionMaximum == 0
        ? "0.08"
        : (0.12 + 0.68 * count.Value / CoMentionMaximum).ToString("0.00", System.Globalization.CultureInfo.InvariantCulture);

    private static string EntityId(string category, string name) => $"{category}\u001f{name.ToUpperInvariant()}";
    private static string PairKey(string left, string right) => string.CompareOrdinal(left, right) <= 0 ? $"{left}\u001e{right}" : $"{right}\u001e{left}";

    private sealed class MutableEntity(string name, string key, string label)
    {
        public string Name { get; } = name;
        public string Key { get; } = key;
        public string Label { get; } = label;
        public HashSet<long> CurrentArticleIds { get; } = [];
        public HashSet<long> PreviousArticleIds { get; } = [];
        public InsightEntity ToInsightEntity() => new(Name, Key, Label, CurrentArticleIds.Count,
            CurrentArticleIds.Count - PreviousArticleIds.Count, PreviousArticleIds.Count);
    }
}

public sealed record InsightCategory(string Key, string Label, int EntityCount, IReadOnlyList<InsightEntity> Entities);
public sealed record InsightEntity(string Name, string CategoryKey, string CategoryLabel, int ArticleCount, int Change, int PreviousArticleCount);
public sealed record InsightTreemapTile(InsightEntity Entity, double Left, double Top, double Width, double Height)
{
    public string Style => FormattableString.Invariant($"left:calc({Left:0.###}% + 2px);top:calc({Top:0.###}% + 2px);width:calc({Width:0.###}% - 4px);height:calc({Height:0.###}% - 4px);");
}
public sealed record ActivityBucket(string Label, int ArticleCount, double X, double Y, bool ShowLabel);
public sealed record CoMentionCell(InsightEntity Entity, int? ArticleCount);
public sealed record CoMentionRow(InsightEntity Entity, IReadOnlyList<CoMentionCell> Cells);
