using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;

namespace ThreatIntelAggro.Pages;

public sealed class GraphModel(AppDatabase database) : PageModel
{
    public static readonly (string Key, string Label)[] AvailableTypes =
    [
        ("source", "Source"), ("article", "Article"), ("vendor", "Vendor"), ("product", "Product"),
        ("industry", "Industry"), ("actor", "Threat actor"), ("malware", "Malware"), ("campaign", "Campaign"),
        ("vulnerability", "Vulnerability"), ("country", "Targeted country"), ("ioc", "IOC"),
        ("technique", "MITRE technique"), ("detection", "Detection"), ("recommendation", "Recommendation")
    ];

    public string Scope { get; private set; } = "";
    public string? Search { get; private set; }
    public string? Category { get; private set; }
    public string? Source { get; private set; }
    public string? IocStatus { get; private set; }
    public int Days { get; private set; } = 90;
    public bool CoMentions { get; private set; }
    public IReadOnlySet<string> SelectedTypes { get; private set; } = AvailableTypes.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<string> Categories { get; private set; } = [];
    public IReadOnlyList<string> Sources { get; private set; } = [];
    public ThreatGraphData Graph { get; private set; } = ThreatGraphData.Empty();
    public IReadOnlyList<ThreatGraphPosition> Positions { get; private set; } = [];
    private IReadOnlyDictionary<string, ThreatGraphPosition> PositionMap { get; set; } = new Dictionary<string, ThreatGraphPosition>(StringComparer.OrdinalIgnoreCase);
    public ThreatGraphPosition? PositionFor(string id) => PositionMap.GetValueOrDefault(id);
    public string FirstSelectedId => Graph.Nodes.FirstOrDefault(node => Scope == "search" && !string.IsNullOrWhiteSpace(Search) && node.Label.Contains(Search, StringComparison.OrdinalIgnoreCase))?.Id ?? Graph.Nodes.FirstOrDefault(node => node.Type == "article")?.Id ?? Graph.Nodes.FirstOrDefault()?.Id ?? "";
    public int SvgWidth { get; private set; } = 980;
    public int SvgHeight { get; private set; } = 520;

    [BindProperty(SupportsGet = true)] public string? ScopeInput { get; set; }
    [BindProperty(SupportsGet = true)] public string? ScopeOverride { get; set; }
    [BindProperty(SupportsGet = true)] public string? SearchInput { get; set; }
    [BindProperty(SupportsGet = true)] public string? CategoryInput { get; set; }
    [BindProperty(SupportsGet = true)] public string? SourceInput { get; set; }
    [BindProperty(SupportsGet = true)] public string? IocStatusInput { get; set; }
    [BindProperty(SupportsGet = true)] public int? DaysInput { get; set; }
    [BindProperty(SupportsGet = true)] public bool CoMentionsInput { get; set; }
    [BindProperty(SupportsGet = true)] public string[]? TypesInput { get; set; }
    [BindProperty(SupportsGet = true)] public bool TypesSpecified { get; set; }

    public void OnGet() => Load();

    public IActionResult OnGetExportData()
    {
        Load();
        var payload = new
        {
            scope = Scope,
            filters = new { query = Search, category = Category, source = Source, iocStatus = IocStatus, days = Days, coMentions = CoMentions },
            nodes = Graph.Nodes,
            relationships = Graph.Edges
        };
        return File(JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions { WriteIndented = true }), "application/json; charset=utf-8", "threat-intel-graph.json");
    }

    private void Load()
    {
        Search = string.IsNullOrWhiteSpace(SearchInput) ? null : SearchInput.Trim();
        Category = string.IsNullOrWhiteSpace(CategoryInput) ? null : CategoryInput.Trim();
        Source = string.IsNullOrWhiteSpace(SourceInput) ? null : SourceInput.Trim();
        IocStatus = string.IsNullOrWhiteSpace(IocStatusInput) || IocStatusInput == "all" ? null : IocStatusInput.Trim();
        Days = ScopeOverride == "all" ? 0 : ScopeOverride == "recent" ? 30 : DaysInput is 7 or 30 or 90 or 365 or 0 ? DaysInput.Value : 90;
        CoMentions = CoMentionsInput;
        Scope = NormalizeScope(ScopeOverride) ?? NormalizeScope(ScopeInput) ?? (Search is not null ? "search" : "");
        if (ScopeOverride == "recent") Category = ArticleCategories.TimeCritical;
        else if (Scope == "recent" && Category is null && ScopeInput == "recent" && CategoryInput is null) Category = ArticleCategories.TimeCritical;

        var validTypeKeys = AvailableTypes.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        SelectedTypes = TypesSpecified
            ? (TypesInput ?? []).Where(validTypeKeys.Contains).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : validTypeKeys;

        Categories = database.Query("SELECT DISTINCT category FROM articles WHERE ai_status='analyzed' AND evidence_verified=1 AND analysis_json IS NOT NULL AND TRIM(category)<>'' ORDER BY category COLLATE NOCASE")
            .Select(row => row.GetValueOrDefault("category") ?? "").Where(value => value.Length > 0).ToArray();
        Sources = database.Query("SELECT DISTINCT feed_title FROM articles WHERE ai_status='analyzed' AND evidence_verified=1 AND analysis_json IS NOT NULL AND TRIM(feed_title)<>'' ORDER BY feed_title COLLATE NOCASE")
            .Select(row => row.GetValueOrDefault("feed_title") ?? "").Where(value => value.Length > 0).ToArray();

        Graph = ThreatGraphBuilder.Build(database, new ThreatGraphQuery(Scope, Search, Category, Source, IocStatus, Days, CoMentions, SelectedTypes, TypesSpecified));
        if (Graph.Nodes.Count == 0) return;
        LayoutGraph();
    }

    private void LayoutGraph()
    {
        var laneOrder = AvailableTypes.Select((item, index) => (item.Key, Index: index)).ToDictionary(pair => pair.Key, pair => pair.Index, StringComparer.OrdinalIgnoreCase);
        var groups = Graph.Nodes.GroupBy(node => node.Type).OrderBy(group => laneOrder.GetValueOrDefault(group.Key, 99)).ToArray();
        const int groupsPerRow = 4;
        const int groupColumnPitch = 245;
        const int nodeRowPitch = 92;
        const int typeRowGap = 24;
        var groupRows = groups.Chunk(groupsPerRow).ToArray();
        var groupRowHeights = groupRows.Select(row => row.Max(group => group.Count()) * nodeRowPitch + typeRowGap).ToArray();
        SvgWidth = Math.Max(980, Math.Min(groupsPerRow, groups.Length) * groupColumnPitch + 120);
        SvgHeight = Math.Max(520, 35 + groupRowHeights.Sum());
        var positions = new List<ThreatGraphPosition>(Graph.Nodes.Count);
        var selectedId = FirstSelectedId;
        var groupIndex = 0;
        foreach (var group in groups)
        {
            var groupRow = groupIndex / groupsPerRow;
            var groupColumn = groupIndex % groupsPerRow;
            var rowTop = 35 + groupRowHeights.Take(groupRow).Sum();
            var index = 0;
            foreach (var node in group)
            {
                var x = 135 + groupColumn * groupColumnPitch;
                var y = rowTop + 35 + index * nodeRowPitch;
                positions.Add(new ThreatGraphPosition(node, x, y, ShortLabel(node.Label, 25), node.Id == selectedId));
                index++;
            }
            groupIndex++;
        }
        Positions = positions;
        PositionMap = positions.ToDictionary(position => position.Node.Id, StringComparer.OrdinalIgnoreCase);
    }

    private static string? NormalizeScope(string? scope) => scope?.Trim().ToLowerInvariant() switch
    {
        "search" or "recent" or "all" => scope.Trim().ToLowerInvariant(),
        _ => null
    };

    private static string ShortLabel(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";
}

public sealed record ThreatGraphPosition(ThreatGraphNode Node, int X, int Y, string ShortLabel, bool Selected);
