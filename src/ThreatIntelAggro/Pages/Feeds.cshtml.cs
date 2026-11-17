using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Xml;
using System.Xml.Linq;

namespace ThreatIntelAggro.Pages;

[RequestSizeLimit(3_000_000)]
public class FeedsModel(AppDatabase database, FeedReader reader) : PageModel
{
    public IReadOnlyList<Dictionary<string, string?>> Feeds { get; private set; } = [];
    [BindProperty] public string Title { get; set; } = "";
    [BindProperty] public string FeedUrl { get; set; } = "";
    [BindProperty] public int IntervalHours { get; set; } = 6;
    [BindProperty] public bool IocAutoApprove { get; set; }
    [BindProperty] public string GitHubRepositoryUrl { get; set; } = "";
    [TempData] public string? Notice { get; set; }
    [BindProperty] public string OpmlText { get; set; } = "";
    [BindProperty] public IFormFile? OpmlFile { get; set; }
    [BindProperty(SupportsGet = true)] public string? Search { get; set; }
    [BindProperty(SupportsGet = true)] public string Status { get; set; } = "all";
    [BindProperty(SupportsGet = true)] public string Cadence { get; set; } = "all";
    [BindProperty(SupportsGet = true)] public string IocApproval { get; set; } = "all";
    [BindProperty(SupportsGet = true)] public string Sort { get; set; } = "name";
    [BindProperty(SupportsGet = true)] public string Direction { get; set; } = "asc";
    public int TotalFeedCount { get; private set; }

    public string NextDirection(string column) => Sort == column && Direction == "asc" ? "desc" : "asc";
    public string SortIndicator(string column) => Sort != column ? "↕" : Direction == "asc" ? "▲" : "▼";

    public void OnGet()
    {
        NormalizeFilters();
        Load();
    }

    public IActionResult OnPostAdd()
    {
        Title = Title.Trim(); FeedUrl = FeedUrl.Trim();
        if (Title.Length is < 2 or > 100 || !Uri.TryCreate(FeedUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            ModelState.AddModelError("", "Enter a feed name and a valid public HTTP or HTTPS URL."); NormalizeFilters(); Load(); return Page();
        }
        if (!new[] { 3, 6, 12, 24 }.Contains(IntervalHours)) IntervalHours = 6;
        try
        {
            database.Execute("INSERT INTO feeds(title,url,interval_hours,enabled,ioc_auto_approve,created_utc) VALUES(?,?,?,?,?,?)", Title, uri.ToString(), IntervalHours, 1, IocAutoApprove, DateTimeOffset.UtcNow.ToString("O"));
            Notice = "Feed added. Its first poll starts shortly.";
            return RedirectToCurrentView();
        }
        catch (Exception exception) when (exception.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError("", "That feed URL is already on your list."); NormalizeFilters(); Load(); return Page();
        }
    }

    public IActionResult OnPostAddGitHubRepository()
    {
        GitHubRepositoryUrl = GitHubRepositoryUrl.Trim();
        if (!TryNormalizeGitHubRepository(GitHubRepositoryUrl, out var repositoryUrl))
        {
            Notice = "Enter a public GitHub repository URL such as https://github.com/owner/repository.";
            return RedirectToCurrentView();
        }
        if (!new[] { 3, 6, 12, 24 }.Contains(IntervalHours)) IntervalHours = 6;
        var repository = new Uri(repositoryUrl).AbsolutePath.Trim('/');
        var title = $"GitHub · {repository}";
        try
        {
            database.Execute("INSERT INTO feeds(title,url,interval_hours,enabled,ioc_auto_approve,source_type,created_utc) VALUES(?,?,?,?,0,'github',?)",
                title, repositoryUrl, IntervalHours, 1, DateTimeOffset.UtcNow.ToString("O"));
            Notice = "GitHub repository added. Its first advisory poll starts shortly.";
            return RedirectToCurrentView();
        }
        catch (Exception exception) when (exception.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase))
        {
            Notice = "That GitHub repository is already on your list.";
            return RedirectToCurrentView();
        }
    }

    public async Task<IActionResult> OnPostRefreshAsync(long id, CancellationToken cancellationToken)
    {
        try { var count = await reader.RefreshAsync(id, cancellationToken); Notice = $"Refresh complete. {count} new article{(count == 1 ? "" : "s")} found."; }
        catch (Exception exception) when (exception is not OperationCanceledException) { Notice = $"Refresh failed: {exception.Message}"; }
        return RedirectToCurrentView();
    }

    public IActionResult OnPostToggle(long id)
    {
        database.Execute("UPDATE feeds SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", id);
        Notice = "Feed status updated."; return RedirectToCurrentView();
    }

    public IActionResult OnPostEdit(long id, string title, int intervalHours, string? feedUrl, bool iocAutoApprove)
    {
        title = title.Trim();
        var current = database.Query("SELECT url,source_type FROM feeds WHERE id=?", id).FirstOrDefault();
        var url = string.IsNullOrWhiteSpace(feedUrl) ? current?["url"] : feedUrl.Trim();
        var isGitHub = current?.GetValueOrDefault("source_type") == "github";
        if (isGitHub && TryNormalizeGitHubRepository(url ?? "", out var normalizedRepository)) url = normalizedRepository;
        Uri? uri = null;
        var validUrl = isGitHub ? TryNormalizeGitHubRepository(url ?? "", out _) : Uri.TryCreate(url, UriKind.Absolute, out uri) && uri is not null && (uri.Scheme is "http" or "https") && string.IsNullOrEmpty(uri.UserInfo);
        if (title.Length is < 2 or > 100 || !new[] { 3, 6, 12, 24 }.Contains(intervalHours) || !validUrl)
        {
            Notice = "Feed name, URL, or interval is invalid."; return RedirectToCurrentView();
        }
        try { database.Execute("UPDATE feeds SET title=?,url=?,interval_hours=?,ioc_auto_approve=?,last_checked_utc=NULL WHERE id=?", title, isGitHub ? url : uri!.ToString(), intervalHours, iocAutoApprove, id); }
        catch (Exception e) when (e.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase)) { Notice = "Another source already uses that feed URL."; return RedirectToCurrentView(); }
        database.Execute("UPDATE articles SET feed_title=? WHERE feed_id=?", title, id);
        if (iocAutoApprove)
            foreach (var article in database.Query("SELECT id,analysis_json FROM articles WHERE feed_id=? AND analysis_json IS NOT NULL AND evidence_verified=1 AND ai_status='analyzed'", id))
                IocIndex.ApproveArticle(database, long.Parse(article["id"]!), article["analysis_json"]);
        Notice = "Feed updated."; return RedirectToCurrentView();
    }

    public IActionResult OnPostRemove(long id)
    {
        database.Execute("DELETE FROM feeds WHERE id=?", id);
        Notice = "Feed removed. Previously collected articles remain in your inbox."; return RedirectToCurrentView();
    }

    public async Task<IActionResult> OnPostImportOpmlAsync(CancellationToken cancellationToken)
    {
        var opml = OpmlText;
        if (OpmlFile is { Length: > 0 })
        {
            if (OpmlFile.Length > 2_000_000) { Notice = "OPML file exceeds the 2 MB import limit."; return RedirectToCurrentView(); }
            using var file = new StreamReader(OpmlFile.OpenReadStream());
            opml = await file.ReadToEndAsync(cancellationToken);
        }
        if (string.IsNullOrWhiteSpace(opml) || opml.Length > 2_000_000)
        {
            Notice = "OPML is empty or exceeds the 2 MB import limit.";
            return RedirectToCurrentView();
        }
        try
        {
            using var input = new StringReader(opml);
            using var xml = XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 2_000_000 });
            var document = XDocument.Load(xml);
            var added = 0; var skipped = 0;
            foreach (var outline in document.Descendants().Where(x => x.Name.LocalName == "outline" && x.Attribute("xmlUrl") is not null))
            {
                var address = ((string?)outline.Attribute("xmlUrl") ?? "").Trim();
                if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo)) { skipped++; continue; }
                var title = ((string?)outline.Attribute("title") ?? (string?)outline.Attribute("text") ?? uri.Host).Trim();
                if (title.Length < 2) title = uri.Host;
                if (title.Length > 100) title = title[..100];
                try { added += database.Execute("INSERT OR IGNORE INTO feeds(title,url,interval_hours,enabled,created_utc) VALUES(?,?,?,?,?)", title, uri.ToString(), 6, 1, DateTimeOffset.UtcNow.ToString("O")); }
                catch { skipped++; }
            }
            Notice = $"OPML import complete: {added} feed{(added == 1 ? "" : "s")} added; {skipped} invalid entries skipped; duplicates were ignored.";
        }
        catch (Exception ex) { Notice = $"OPML could not be read: {ex.Message[..Math.Min(250, ex.Message.Length)]}"; }
        return RedirectToCurrentView();
    }

    private void Load()
    {
        TotalFeedCount = database.ScalarInt("SELECT COUNT(*) FROM feeds");
        var conditions = new List<string>();
        var args = new List<object?>();
        if (Status == "unreachable") conditions.Add("f.last_error IS NOT NULL AND length(trim(f.last_error))>0");
        else if (Status == "active") conditions.Add("f.enabled=1 AND (f.last_error IS NULL OR length(trim(f.last_error))=0)");
        else if (Status == "paused") conditions.Add("f.enabled=0");
        if (Cadence != "all") { conditions.Add("f.interval_hours=?"); args.Add(int.Parse(Cadence)); }
        if (IocApproval == "enabled") conditions.Add("f.ioc_auto_approve=1");
        else if (IocApproval == "disabled") conditions.Add("f.ioc_auto_approve=0");
        if (!string.IsNullOrWhiteSpace(Search))
        {
            conditions.Add("(f.title LIKE ? OR f.url LIKE ?)");
            var term = $"%{Search.Trim()}%";
            args.Add(term); args.Add(term);
        }
        var where = conditions.Count == 0 ? "" : "WHERE " + string.Join(" AND ", conditions);
        var direction = Direction == "desc" ? "DESC" : "ASC";
        var ordering = Sort switch
        {
            "cadence" => $"f.interval_hours {direction},f.title COLLATE NOCASE ASC,f.id ASC",
            "articles" => $"article_count {direction},f.title COLLATE NOCASE ASC,f.id ASC",
            "checked" => $"(f.last_checked_utc IS NULL) ASC,f.last_checked_utc {direction},f.title COLLATE NOCASE ASC,f.id ASC",
            "status" => $"CASE WHEN f.last_error IS NOT NULL AND length(trim(f.last_error))>0 THEN 0 WHEN f.enabled=1 THEN 1 ELSE 2 END {direction},f.title COLLATE NOCASE ASC,f.id ASC",
            _ => $"f.title COLLATE NOCASE {direction},f.id ASC"
        };
        Feeds = database.Query($"SELECT f.id,f.title,f.url,f.source_type,f.interval_hours,f.enabled,f.ioc_auto_approve,f.last_checked_utc,f.last_error,(SELECT COUNT(*) FROM articles a WHERE a.feed_id=f.id) AS article_count FROM feeds f {where} ORDER BY {ordering}", args.ToArray());
    }

    private void NormalizeFilters()
    {
        Search = string.IsNullOrWhiteSpace(Search) ? null : Search.Trim()[..Math.Min(Search.Trim().Length, 200)];
        if (Status is not ("all" or "unreachable" or "active" or "paused")) Status = "all";
        if (Cadence is not ("all" or "3" or "6" or "12" or "24")) Cadence = "all";
        if (IocApproval is not ("all" or "enabled" or "disabled")) IocApproval = "all";
        if (Sort is not ("name" or "cadence" or "articles" or "checked" or "status")) Sort = "name";
        if (Direction is not ("asc" or "desc")) Direction = "asc";
    }

    private IActionResult RedirectToCurrentView() => RedirectToPage("/Feeds", new { search = Search, status = Status, cadence = Cadence, iocApproval = IocApproval, sort = Sort, direction = Direction });

    private static bool TryNormalizeGitHubRepository(string value, out string canonicalUrl)
    {
        canonicalUrl = "";
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        var parts = uri.AbsolutePath.Trim('/').Split('/');
        if (parts.Length != 2 || !System.Text.RegularExpressions.Regex.IsMatch(parts[0], "^[A-Za-z0-9-]+$") ||
            !System.Text.RegularExpressions.Regex.IsMatch(parts[1], "^[A-Za-z0-9_.-]+$") || parts[1] is "." or ".." ||
            parts[1].EndsWith(".git", StringComparison.OrdinalIgnoreCase)) return false;
        canonicalUrl = $"https://github.com/{parts[0].ToLowerInvariant()}/{parts[1].ToLowerInvariant()}";
        return true;
    }
}
