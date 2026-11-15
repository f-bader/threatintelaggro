using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public class InboxModel(AppDatabase database, AnalysisService analyzer) : PageModel
{
    public IReadOnlyList<Dictionary<string, string?>> Articles { get; private set; } = [];
    public int UnreadCount { get; private set; }
    public int FeedCount { get; private set; }
    public int TodayCount { get; private set; }
    public int TotalCount { get; private set; }
    public string[] Industries { get; private set; } = [];
    public string[] Vendors { get; private set; } = [];
    public string[] MitreMappings { get; private set; } = [];
    public string[] ThreatActors { get; private set; } = [];
    public string[] CategoryOptions => ArticleCategories.PriorityOrder;
    public int ActiveFilterCount => new[] { Industry, Vendor, Mitre, ThreatActor, Category }.Count(x => !string.IsNullOrWhiteSpace(x));
    public string[] VisibleIocs(System.Text.Json.JsonElement root, string? articleId) => IocIndex.IocValues(database, root, articleId);
    public int DetectionCount(string? articleId) => long.TryParse(articleId, out var id) ? database.ScalarInt("SELECT COUNT(*) FROM detections WHERE article_id=?", id) : 0;
    [TempData] public string? Notice { get; set; }
    [BindProperty(SupportsGet = true)] public string? Search { get; set; }
    [BindProperty(SupportsGet = true)] public string State { get; set; } = "unread";
    [BindProperty(SupportsGet = true)] public string? Industry { get; set; }
    [BindProperty(SupportsGet = true)] public string? Vendor { get; set; }
    [BindProperty(SupportsGet = true)] public string? Mitre { get; set; }
    [BindProperty(SupportsGet = true)] public string? ThreatActor { get; set; }
    [BindProperty(SupportsGet = true)] public bool FiltersOpen { get; set; }
    [BindProperty(SupportsGet = true)] public string? Category { get; set; }
    [BindProperty(SupportsGet = true)] public string Sort { get; set; } = "recent";
    [BindProperty] public string AdHocUrl { get; set; } = "";

    public void OnGet()
    {
        if (!ArticleCategories.IsValid(Category)) Category = null;
        Sort = Sort == "priority" ? "priority" : "recent";
        RefreshAdHocSummaries();
        UnreadCount = database.ScalarInt("SELECT COUNT(*) FROM articles WHERE is_read=0");
        FeedCount = database.ScalarInt("SELECT COUNT(*) FROM feeds WHERE enabled=1");
        TodayCount = database.ScalarInt("SELECT COUNT(*) FROM articles WHERE first_seen_utc >= ?", DateTimeOffset.UtcNow.Date.ToString("O"));
        TotalCount = database.ScalarInt("SELECT COUNT(*) FROM articles");
        Industries = IocIndex.Options(database, "industries");
        Vendors = IocIndex.Options(database, "vendors");
        MitreMappings = IocIndex.Options(database, "mitre_mappings");
        ThreatActors = IocIndex.Options(database, "threat_actors");
        var conditions = new List<string>();
        var args = new List<object?>();
        if (State == "unread") conditions.Add("is_read=0");
        else if (State == "read") conditions.Add("is_read=1");
        if (!string.IsNullOrWhiteSpace(Category)) { conditions.Add("category=?"); args.Add(Category); }
        if (!string.IsNullOrWhiteSpace(Search))
        {
            conditions.Add("(title LIKE ? OR summary LIKE ? OR feed_title LIKE ?)");
            var term = $"%{Search.Trim()}%";
            args.Add(term); args.Add(term); args.Add(term);
        }
        var where = conditions.Count == 0 ? "" : "WHERE " + string.Join(" AND ", conditions);
        var ordering = Sort == "priority"
            ? "CASE category WHEN 'Time-Critical Threat' THEN 0 WHEN 'Novel Research' THEN 1 WHEN 'Actionable IOCs' THEN 2 WHEN 'Existing Research' THEN 3 ELSE 4 END,COALESCE(published_utc,first_seen_utc) DESC"
            : "COALESCE(published_utc,first_seen_utc) DESC";
        var articles = database.Query($"SELECT id,title,url,summary,published_utc,first_seen_utc,is_read,feed_title,ai_status,ai_error,analysis_json,source_ledger_json,category FROM articles {where} ORDER BY {ordering} LIMIT 1000", args.ToArray());
        Articles = articles.Where(MatchesMappings).Take(100).ToArray();
    }

    public string CategoryClass(string? category) => ArticleCategories.Normalize(category) switch
    {
        ArticleCategories.TimeCritical => "time-critical",
        ArticleCategories.NovelResearch => "novel",
        ArticleCategories.ActionableIocs => "actionable",
        ArticleCategories.Discard => "discard",
        _ => "existing"
    };

    public string CategoryRationale(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return "Analyst-set article category.";
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("category_rationale", out var rationale) ? rationale.GetString() ?? "Analyst-set article category." : "Analyst-set article category.";
        }
        catch (System.Text.Json.JsonException) { return "Analyst-set article category."; }
    }

    public IActionResult OnPostCategory(long id, string? selectedCategory, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? categoryFilter, string? sort)
    {
        if (ArticleCategories.IsValid(selectedCategory))
            database.Execute("UPDATE articles SET category=?,category_manual=1 WHERE id=?", ArticleCategories.Normalize(selectedCategory), id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, mitre, threatActor, filtersOpen, category = categoryFilter, sort = sort == "priority" ? "priority" : "recent" });
    }

    private void RefreshAdHocSummaries()
    {
        foreach (var article in database.Query("SELECT id,analysis_json FROM articles WHERE (feed_title LIKE 'Ad hoc · %' OR summary='Submitted for one-off analysis.') AND analysis_json IS NOT NULL"))
        {
            try
            {
                using var document = System.Text.Json.JsonDocument.Parse(article["analysis_json"]!);
                var summary = document.RootElement.GetProperty("summary").GetProperty("overview").GetString();
                if (!string.IsNullOrWhiteSpace(summary)) database.Execute("UPDATE articles SET summary=? WHERE id=?", summary.Length > 1200 ? summary[..1200] : summary, article["id"]);
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or KeyNotFoundException or InvalidOperationException) { }
        }
    }

    private bool MatchesMappings(Dictionary<string, string?> article)
    {
        if (string.IsNullOrWhiteSpace(Industry) && string.IsNullOrWhiteSpace(Vendor) && string.IsNullOrWhiteSpace(Mitre) && string.IsNullOrWhiteSpace(ThreatActor)) return true;
        if (string.IsNullOrWhiteSpace(article["analysis_json"])) return false;
        try
        {
            using var json = System.Text.Json.JsonDocument.Parse(article["analysis_json"]!);
            var root = json.RootElement;
            return Includes("industries", Industry) && Includes("vendors", Vendor) && Includes("mitre_mappings", Mitre) && Includes("threat_actors", ThreatActor);
            bool Includes(string field, string? selected) => string.IsNullOrWhiteSpace(selected) || IocIndex.Values(root, field).Any(x => x.Equals(selected, StringComparison.OrdinalIgnoreCase));
        }
        catch (System.Text.Json.JsonException) { return false; }
    }

    public IActionResult OnPostRead(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort)
    {
        database.Execute("UPDATE articles SET is_read=1 WHERE id=?", id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, mitre, threatActor, filtersOpen, category, sort });
    }

    public IActionResult OnPostUnread(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort)
    {
        database.Execute("UPDATE articles SET is_read=0 WHERE id=?", id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, mitre, threatActor, filtersOpen, category, sort });
    }

    public IActionResult OnPostAnalyze(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort)
    {
        analyzer.QueueAnalysis(id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, mitre, threatActor, filtersOpen, category, sort });
    }

    public IActionResult OnPostReanalyze(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort)
    {
        analyzer.QueueReanalysis(id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, mitre, threatActor, filtersOpen, category, sort });
    }

    public IActionResult OnPostAdHocAnalyze()
    {
        AdHocUrl = AdHocUrl.Trim();
        if (AdHocUrl.Length > 2048 || !Uri.TryCreate(AdHocUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            ModelState.AddModelError(nameof(AdHocUrl), "Enter a valid public HTTP or HTTPS website URL.");
            OnGet();
            return Page();
        }

        var articleUrl = uri.GetComponents(UriComponents.HttpRequestUrl, UriFormat.UriEscaped);
        var existing = database.Query("SELECT id,ai_status FROM articles WHERE url=? ORDER BY id DESC LIMIT 1", articleUrl).FirstOrDefault();
        if (existing is not null)
        {
            var existingId = long.Parse(existing["id"]!);
            var status = existing["ai_status"] ?? "pending";
            if (status == "failed")
            {
                analyzer.QueueAnalysis(existingId);
                Notice = "This page is already in your inbox. Its failed analysis has been queued to retry.";
            }
            else
            {
                Notice = status == "analyzed"
                    ? "This page is already analyzed in your inbox; no duplicate analysis was queued."
                    : "This page is already in your inbox and its analysis is queued or in progress.";
            }
            return RedirectToPage();
        }

        var pageName = Uri.UnescapeDataString(uri.Segments.LastOrDefault()?.Trim('/') ?? "");
        if (string.IsNullOrWhiteSpace(pageName)) pageName = uri.Host;
        if (pageName.Length > 400) pageName = pageName[..400];
        var now = DateTimeOffset.UtcNow.ToString("O");
        var feedTitle = $"Ad hoc · {uri.Host}";
        database.Execute("INSERT INTO articles(feed_id,feed_title,title,url,summary,published_utc,first_seen_utc,ai_status) VALUES(NULL,?,?,?,?,?,?,?)",
            feedTitle, pageName, articleUrl, "Submitted for one-off analysis.", null, now, "pending");
        Notice = "Page added to your inbox and analysis queued. Follow its progress below.";
        return RedirectToPage();
    }
}
