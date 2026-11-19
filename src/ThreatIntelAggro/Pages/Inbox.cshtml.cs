using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text.Json;

namespace ThreatIntelAggro.Pages;

public sealed record InboxArticleGroup(ArticleGroup Group, IReadOnlyList<Dictionary<string, string?>> MatchingMembers);

[RequestSizeLimit(12_000_000)]
[RequestFormLimits(MultipartBodyLengthLimit = 12_000_000)]
public class InboxModel(AppDatabase database, AnalysisService analyzer, ArticleGroupingService? grouping = null) : PageModel
{
    public IReadOnlyList<Dictionary<string, string?>> Articles { get; private set; } = [];
    public IReadOnlyList<InboxArticleGroup> ArticleGroups { get; private set; } = [];
    public int ResultCount => Articles.Count + ArticleGroups.Count;
    public int UnreadCount { get; private set; }
    public int FeedCount { get; private set; }
    public int TodayCount { get; private set; }
    public int TotalCount { get; private set; }
    public int DisplaySummaryLimit => 500;
    public string[] Industries { get; private set; } = [];
    public string[] Vendors { get; private set; } = [];
    public string[] Products { get; private set; } = [];
    public string[] MitreMappings { get; private set; } = [];
    public string[] ThreatActors { get; private set; } = [];
    public string[] CategoryOptions => ArticleCategories.PriorityOrder;
    public int ActiveFilterCount => new[] { Industry, Vendor, Product, Mitre, ThreatActor, Category }.Count(x => !string.IsNullOrWhiteSpace(x)) + (FollowedOnly ? 1 : 0);
    public string[] VisibleIocs(System.Text.Json.JsonElement root, string? articleId) => IocIndex.IocValues(database, root, articleId);
    public int DetectionCount(string? articleId) => long.TryParse(articleId, out var id) ? database.ScalarInt("SELECT COUNT(*) FROM detections WHERE article_id=?", id) : 0;
    [TempData] public string? Notice { get; set; }
    [BindProperty(SupportsGet = true)] public string? Search { get; set; }
    [BindProperty(SupportsGet = true)] public string State { get; set; } = "unread";
    [BindProperty(SupportsGet = true)] public string? Industry { get; set; }
    [BindProperty(SupportsGet = true)] public string? Vendor { get; set; }
    [BindProperty(SupportsGet = true)] public string? Product { get; set; }
    [BindProperty(SupportsGet = true)] public string? Mitre { get; set; }
    [BindProperty(SupportsGet = true)] public string? ThreatActor { get; set; }
    [BindProperty(SupportsGet = true)] public bool FollowedOnly { get; set; }
    [BindProperty(SupportsGet = true)] public bool FiltersOpen { get; set; }
    [BindProperty(SupportsGet = true)] public string? Category { get; set; }
    [BindProperty(SupportsGet = true)] public string Sort { get; set; } = "recent";
    [BindProperty(SupportsGet = true)] public string GroupView { get; set; } = "articles";
    [BindProperty(SupportsGet = true)] public bool ShowIgnoredGroups { get; set; }
    [BindProperty] public string AdHocUrl { get; set; } = "";
    [BindProperty] public IFormFile? AdHocImage { get; set; }
    [BindProperty] public List<long> SelectedIds { get; set; } = [];

    public string ReturnUrl => $"{Request.Path}{Request.QueryString}";

    public async Task OnGetAsync(CancellationToken cancellationToken = default)
    {
        if (!ArticleCategories.IsValid(Category)) Category = null;
        Sort = Sort == "priority" ? "priority" : "recent";
        GroupView = GroupView is "duplicates" or "topics" ? GroupView : "articles";
        RefreshAdHocSummaries();
        UnreadCount = database.ScalarInt("SELECT COUNT(*) FROM articles WHERE is_read=0");
        FeedCount = database.ScalarInt("SELECT COUNT(*) FROM feeds WHERE enabled=1");
        TodayCount = database.ScalarInt("SELECT COUNT(*) FROM articles WHERE first_seen_utc >= ?", DateTimeOffset.UtcNow.Date.ToString("O"));
        TotalCount = database.ScalarInt("SELECT COUNT(*) FROM articles");
        Industries = IocIndex.Options(database, "industries");
        Vendors = IocIndex.Options(database, "vendors");
        Products = IocIndex.Options(database, "products");
        MitreMappings = IocIndex.Options(database, "mitre_mappings");
        ThreatActors = IocIndex.Options(database, "threat_actors");
        var follows = database.Query("SELECT kind,name FROM briefing_follows WHERE is_enabled=1")
            .Select(x => (Kind: x["kind"] ?? "", Name: x["name"] ?? ""))
            .Where(x => x.Name.Length > 0).ToArray();
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
        var select = "SELECT id,title,url,summary,published_utc,first_seen_utc,is_read,feed_title,ai_status,ai_error,analysis_json,source_ledger_json,screenshot_metadata_json,CASE WHEN screenshot_data_url IS NOT NULL THEN '1' ELSE '0' END AS has_screenshot,category,evidence_verified FROM articles";
        var articles = database.Query($"{select} {where} ORDER BY {ordering}", args.ToArray());
        var matching = articles.Where(MatchesMappings).Where(article => !FollowedOnly || MatchesFollowed(article, follows)).ToArray();
        if (GroupView == "articles" || grouping is null)
        {
            Articles = matching.Take(100).ToArray();
            return;
        }

        var groupingArticles = database.Query($"{select} ORDER BY {ordering}");
        var candidates = grouping.ReadStored(groupingArticles, GroupView, ShowIgnoredGroups);
        var matchingById = matching.Where(article => long.TryParse(article.GetValueOrDefault("id"), out _))
            .ToDictionary(article => article["id"]!, article => article, StringComparer.Ordinal);
        var claimedArticleIds = new HashSet<string>(StringComparer.Ordinal);
        var displays = new List<InboxArticleGroup>();
        foreach (var group in candidates.OrderByDescending(item => item.Members.Count).ThenBy(item => item.Key, StringComparer.Ordinal))
        {
            var groupMembers = group.Members.Select(member => member.Article.GetValueOrDefault("id"))
                .Where(id => id is not null && matchingById.ContainsKey(id) && !claimedArticleIds.Contains(id))
                .Select(id => matchingById[id!]).ToArray();
            if (groupMembers.Length == 0) continue;
            displays.Add(new InboxArticleGroup(group, groupMembers));
            foreach (var member in groupMembers) claimedArticleIds.Add(member["id"]!);
            if (displays.Count == 100) break;
        }
        ArticleGroups = displays;
        Articles = matching.Where(article => !claimedArticleIds.Contains(article["id"] ?? "")).Take(Math.Max(0, 100 - displays.Count)).ToArray();
    }

    public string DisplaySummary(string? summary)
    {
        var text = System.Net.WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(summary ?? "", "<[^>]+>", " "));
        text = System.Text.RegularExpressions.Regex.Replace(text, "\\s+", " ").Trim();
        return text.Length > DisplaySummaryLimit ? text[..DisplaySummaryLimit].TrimEnd() + " […]" : text;
    }

    private static bool MatchesFollowed(Dictionary<string, string?> article, (string Kind, string Name)[] follows)
    {
        if (follows.Length == 0 || string.IsNullOrWhiteSpace(article["analysis_json"])) return false;
        try
        {
            using var json = System.Text.Json.JsonDocument.Parse(article["analysis_json"]!);
            var root = json.RootElement;
            return follows.Any(follow => IocIndex.Values(root, follow.Kind switch
            {
                "vendor" => "vendors",
                "industry" => "industries",
                "product" => "products",
                _ => ""
            }).Any(candidate => BriefingMatcher.Matches(follow.Name, candidate)));
        }
        catch (System.Text.Json.JsonException) { return false; }
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

    public string? ScreenshotAuthor(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var name = root.TryGetProperty("author_name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
            var handle = root.TryGetProperty("author_handle", out var h) && h.ValueKind == JsonValueKind.String ? h.GetString() : null;
            var platform = root.TryGetProperty("platform", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
            var badgeShown = root.TryGetProperty("author_verified", out var verified) && verified.ValueKind == JsonValueKind.True;
            var author = string.Join(" · ", new[] { name, string.IsNullOrWhiteSpace(handle) ? null : handle.StartsWith('@') ? handle : "@" + handle }.Where(x => !string.IsNullOrWhiteSpace(x)));
            var platformLabel = platform switch { "x" => "X", "bluesky" => "Bluesky", "other" => "Social platform", _ => null };
            return string.Join(" · ", new[] { author, platformLabel, badgeShown ? "verified badge shown" : null }.Where(x => !string.IsNullOrWhiteSpace(x)));
        }
        catch (JsonException) { return null; }
    }

    public IActionResult OnGetScreenshot(long id)
    {
        var dataUrl = database.Query("SELECT screenshot_data_url FROM articles WHERE id=?", id).FirstOrDefault()?.GetValueOrDefault("screenshot_data_url");
        if (string.IsNullOrWhiteSpace(dataUrl)) return NotFound();
        var comma = dataUrl.IndexOf(',');
        var mediaType = dataUrl[..Math.Max(0, comma)].Replace("data:", "", StringComparison.OrdinalIgnoreCase).Replace(";base64", "", StringComparison.OrdinalIgnoreCase);
        if (comma < 0 || mediaType is not ("image/png" or "image/jpeg" or "image/webp")) return NotFound();
        try
        {
            var bytes = Convert.FromBase64String(dataUrl[(comma + 1)..]);
            Response.Headers.CacheControl = "private, no-store";
            return File(bytes, mediaType);
        }
        catch (FormatException) { return NotFound(); }
    }

    public IActionResult OnPostCategory(long id, string? selectedCategory, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? categoryFilter, string? sort, bool followedOnly = false, string? groupView = "articles")
    {
        if (ArticleCategories.IsValid(selectedCategory))
            database.Execute("UPDATE articles SET category=?,category_manual=1 WHERE id=?", ArticleCategories.Normalize(selectedCategory), id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, product = Product, mitre, threatActor, filtersOpen, category = categoryFilter, sort = sort == "priority" ? "priority" : "recent", followedOnly, groupView });
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
        if (string.IsNullOrWhiteSpace(Industry) && string.IsNullOrWhiteSpace(Vendor) && string.IsNullOrWhiteSpace(Product) && string.IsNullOrWhiteSpace(Mitre) && string.IsNullOrWhiteSpace(ThreatActor)) return true;
        if (string.IsNullOrWhiteSpace(article["analysis_json"])) return false;
        try
        {
            using var json = System.Text.Json.JsonDocument.Parse(article["analysis_json"]!);
            var root = json.RootElement;
            return Includes("industries", Industry) && Includes("vendors", Vendor) && Includes("products", Product) && Includes("mitre_mappings", Mitre) && Includes("threat_actors", ThreatActor);
            bool Includes(string field, string? selected) => string.IsNullOrWhiteSpace(selected) || IocIndex.Values(root, field).Any(x => x.Equals(selected, StringComparison.OrdinalIgnoreCase));
        }
        catch (System.Text.Json.JsonException) { return false; }
    }

    public IActionResult OnPostRead(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort, bool followedOnly = false, string? groupView = "articles")
    {
        database.Execute("UPDATE articles SET is_read=1 WHERE id=?", id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, product = Product, mitre, threatActor, filtersOpen, category, sort, followedOnly, groupView });
    }

    public IActionResult OnPostUnread(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort, bool followedOnly = false, string? groupView = "articles")
    {
        database.Execute("UPDATE articles SET is_read=0 WHERE id=?", id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, product = Product, mitre, threatActor, filtersOpen, category, sort, followedOnly, groupView });
    }

    public IActionResult OnPostAnalyze(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort, bool followedOnly = false, string? groupView = "articles")
    {
        analyzer.QueueAnalysis(id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, product = Product, mitre, threatActor, filtersOpen, category, sort, followedOnly, groupView });
    }

    public IActionResult OnPostReanalyze(long id, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort, bool followedOnly = false, string? groupView = "articles")
    {
        analyzer.QueueReanalysis(id);
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, product = Product, mitre, threatActor, filtersOpen, category, sort, followedOnly, groupView });
    }

    public IActionResult OnPostBulk(string? operation, string? returnState, string? search, string? industry, string? vendor, string? mitre, string? threatActor, bool filtersOpen, string? category, string? sort, bool followedOnly = false, string? groupView = "articles")
    {
        var ids = SelectedIds.Distinct().Where(id => id > 0).Take(100).ToArray();
        var changed = 0;
        foreach (var id in ids)
        {
            switch (operation)
            {
                case "read":
                    changed += database.Execute("UPDATE articles SET is_read=1 WHERE id=? AND is_read=0", id);
                    break;
                case "unread":
                    changed += database.Execute("UPDATE articles SET is_read=0 WHERE id=? AND is_read=1", id);
                    break;
                case "analyze":
                    var status = database.Query("SELECT ai_status FROM articles WHERE id=?", id).FirstOrDefault()?["ai_status"];
                    if (status is "pending" or "failed") { analyzer.QueueAnalysis(id); changed++; }
                    break;
                case "reanalyze":
                    if (analyzer.QueueReanalysis(id)) changed++;
                    break;
            }
        }
        Notice = operation switch
        {
            "read" => $"Marked {changed} article(s) as read.",
            "unread" => $"Marked {changed} article(s) as unread.",
            "analyze" => $"Queued {changed} article(s) for analysis or retry.",
            "reanalyze" => $"Queued {changed} analyzed article(s) for reanalysis.",
            _ => "No bulk action was applied."
        };
        return RedirectToPage(new { state = returnState ?? "unread", search, industry, vendor, product = Product, mitre, threatActor, filtersOpen, category, sort = sort == "priority" ? "priority" : "recent", followedOnly, groupView });
    }

    public IActionResult OnPostRenameGroup(string? groupKey, string? label, string? returnUrl)
    {
        var saved = grouping?.Rename(groupKey ?? "", label ?? "") == true;
        Notice = saved ? "Group name saved." : "Enter a group name between 2 and 100 characters.";
        return ReturnToInbox(returnUrl);
    }

    public IActionResult OnPostIgnoreGroup(string? groupKey, bool ignored, string? returnUrl)
    {
        grouping?.SetIgnored(groupKey ?? "", ignored);
        Notice = ignored ? "Group hidden from suggested coverage." : "Group restored to suggested coverage.";
        return ReturnToInbox(returnUrl);
    }

    public IActionResult OnPostExcludeGroupMember(string? groupKey, long articleId, string? returnUrl)
    {
        grouping?.ExcludeMember(groupKey ?? "", articleId);
        Notice = "Article removed from this group suggestion.";
        return ReturnToInbox(returnUrl);
    }

    private IActionResult ReturnToInbox(string? returnUrl) => !string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl)
        ? LocalRedirect(returnUrl)
        : RedirectToPage(new { groupView = GroupView });

    public async Task<IActionResult> OnPostAdHocAnalyze(CancellationToken cancellationToken)
    {
        AdHocUrl = (AdHocUrl ?? "").Trim();
        Uri? uri = null;
        if (AdHocUrl.Length > 0 && (AdHocUrl.Length > 2048 || !Uri.TryCreate(AdHocUrl, UriKind.Absolute, out uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.UserInfo)))
        {
            ModelState.AddModelError(nameof(AdHocUrl), "Enter a valid public HTTP or HTTPS website URL.");
            await OnGetAsync(cancellationToken);
            return Page();
        }

        if ((AdHocImage is null || AdHocImage.Length == 0) && AdHocUrl.Length == 0)
        {
            ModelState.AddModelError(nameof(AdHocUrl), "Enter a public post URL or choose a screenshot.");
            await OnGetAsync(cancellationToken);
            return Page();
        }

        string? screenshotDataUrl = null;
        string? screenshotHash = null;
        if (AdHocImage is { Length: > 0 } image)
        {
            if (image.Length > 8_000_000)
            {
                ModelState.AddModelError(nameof(AdHocImage), "Choose an image smaller than 8 MB.");
                await OnGetAsync(cancellationToken);
                return Page();
            }

            var bytes = new byte[image.Length];
            await using (var stream = image.OpenReadStream())
            {
                var offset = 0;
                while (offset < bytes.Length)
                {
                    var read = await stream.ReadAsync(bytes.AsMemory(offset), cancellationToken);
                    if (read == 0) break;
                    offset += read;
                }
                if (offset != bytes.Length)
                {
                    ModelState.AddModelError(nameof(AdHocImage), "The uploaded image could not be read completely.");
                    await OnGetAsync(cancellationToken);
                    return Page();
                }
            }

            var mediaType = DetectImageMediaType(bytes);
            if (mediaType is null)
            {
                ModelState.AddModelError(nameof(AdHocImage), "Choose a PNG, JPEG, or WebP image.");
                await OnGetAsync(cancellationToken);
                return Page();
            }
            screenshotHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            screenshotDataUrl = $"data:{mediaType};base64,{Convert.ToBase64String(bytes)}";
        }

        var articleUrl = uri is not null
            ? uri.GetComponents(UriComponents.HttpRequestUrl, UriFormat.UriEscaped)
            : $"https://screenshot.invalid/{screenshotHash}";
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

        var pageName = uri is null ? "Social post screenshot" : Uri.UnescapeDataString(uri.Segments.LastOrDefault()?.Trim('/') ?? "");
        if (string.IsNullOrWhiteSpace(pageName)) pageName = uri?.Host ?? "Social post screenshot";
        if (pageName.Length > 400) pageName = pageName[..400];
        var now = DateTimeOffset.UtcNow.ToString("O");
        var feedTitle = uri is null ? "Ad hoc · Screenshot" : $"Ad hoc · {uri.Host}";
        database.Execute("INSERT INTO articles(feed_id,feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,screenshot_data_url) VALUES(NULL,?,?,?,?,?,?,?,?)",
            feedTitle, pageName, articleUrl, "Submitted for one-off analysis.", null, now, "pending", screenshotDataUrl);
        Notice = screenshotDataUrl is null ? "Page added to your inbox and analysis queued. Follow its progress below." : "Screenshot added to your inbox. AI extraction and analysis are queued.";
        return RedirectToPage();
    }

    private static string? DetectImageMediaType(byte[] bytes)
    {
        if (bytes.Length >= 8 && bytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })) return "image/png";
        if (bytes.Length >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff) return "image/jpeg";
        if (bytes.Length >= 12 && System.Text.Encoding.ASCII.GetString(bytes, 0, 4) == "RIFF" && System.Text.Encoding.ASCII.GetString(bytes, 8, 4) == "WEBP") return "image/webp";
        return null;
    }
}
