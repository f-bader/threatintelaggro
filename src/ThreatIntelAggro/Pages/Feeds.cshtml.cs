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
    [TempData] public string? Notice { get; set; }
    [BindProperty] public string OpmlText { get; set; } = "";
    [BindProperty] public IFormFile? OpmlFile { get; set; }
    [BindProperty(SupportsGet = true)] public string Status { get; set; } = "all";

    public void OnGet() => Load();

    public IActionResult OnPostAdd()
    {
        Title = Title.Trim(); FeedUrl = FeedUrl.Trim();
        if (Title.Length is < 2 or > 100 || !Uri.TryCreate(FeedUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            ModelState.AddModelError("", "Enter a feed name and a valid public HTTP or HTTPS URL."); Load(); return Page();
        }
        if (!new[] { 3, 6, 12, 24 }.Contains(IntervalHours)) IntervalHours = 6;
        try
        {
            database.Execute("INSERT INTO feeds(title,url,interval_hours,enabled,ioc_auto_approve,created_utc) VALUES(?,?,?,?,?,?)", Title, uri.ToString(), IntervalHours, 1, IocAutoApprove, DateTimeOffset.UtcNow.ToString("O"));
            Notice = "Feed added. Its first poll starts shortly.";
            return RedirectToPage();
        }
        catch (Exception exception) when (exception.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError("", "That feed URL is already on your list."); Load(); return Page();
        }
    }

    public async Task<IActionResult> OnPostRefreshAsync(long id, CancellationToken cancellationToken)
    {
        try { var count = await reader.RefreshAsync(id, cancellationToken); Notice = $"Refresh complete. {count} new article{(count == 1 ? "" : "s")} found."; }
        catch (Exception exception) when (exception is not OperationCanceledException) { Notice = $"Refresh failed: {exception.Message}"; }
        return RedirectToPage();
    }

    public IActionResult OnPostToggle(long id)
    {
        database.Execute("UPDATE feeds SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", id);
        Notice = "Feed status updated."; return RedirectToPage();
    }

    public IActionResult OnPostEdit(long id, string title, int intervalHours, string? feedUrl, bool iocAutoApprove)
    {
        title = title.Trim();
        var current = database.Query("SELECT url FROM feeds WHERE id=?", id).FirstOrDefault();
        var url = string.IsNullOrWhiteSpace(feedUrl) ? current?["url"] : feedUrl.Trim();
        if (title.Length is < 2 or > 100 || !new[] { 3, 6, 12, 24 }.Contains(intervalHours) || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            Notice = "Feed name, URL, or interval is invalid."; return RedirectToPage();
        }
        try { database.Execute("UPDATE feeds SET title=?,url=?,interval_hours=?,ioc_auto_approve=?,last_checked_utc=NULL WHERE id=?", title, uri.ToString(), intervalHours, iocAutoApprove, id); }
        catch (Exception e) when (e.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase)) { Notice = "Another source already uses that feed URL."; return RedirectToPage(); }
        database.Execute("UPDATE articles SET feed_title=? WHERE feed_id=?", title, id);
        if (iocAutoApprove)
            foreach (var article in database.Query("SELECT id,analysis_json FROM articles WHERE feed_id=? AND analysis_json IS NOT NULL", id))
                IocIndex.ApproveArticle(database, long.Parse(article["id"]!), article["analysis_json"]);
        Notice = "Feed updated."; return RedirectToPage();
    }

    public IActionResult OnPostRemove(long id)
    {
        database.Execute("DELETE FROM feeds WHERE id=?", id);
        Notice = "Feed removed. Previously collected articles remain in your inbox."; return RedirectToPage();
    }

    public async Task<IActionResult> OnPostImportOpmlAsync(CancellationToken cancellationToken)
    {
        var opml = OpmlText;
        if (OpmlFile is { Length: > 0 })
        {
            if (OpmlFile.Length > 2_000_000) { Notice = "OPML file exceeds the 2 MB import limit."; return RedirectToPage(); }
            using var file = new StreamReader(OpmlFile.OpenReadStream());
            opml = await file.ReadToEndAsync(cancellationToken);
        }
        if (string.IsNullOrWhiteSpace(opml) || opml.Length > 2_000_000)
        {
            Notice = "OPML is empty or exceeds the 2 MB import limit.";
            return RedirectToPage();
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
        return RedirectToPage();
    }

    private void Load()
    {
        var condition = Status switch
        {
            "unreachable" => "WHERE f.last_error IS NOT NULL AND length(trim(f.last_error))>0",
            "active" => "WHERE f.enabled=1 AND (f.last_error IS NULL OR length(trim(f.last_error))=0)",
            "paused" => "WHERE f.enabled=0",
            _ => ""
        };
        Feeds = database.Query($"SELECT f.id,f.title,f.url,f.interval_hours,f.enabled,f.ioc_auto_approve,f.last_checked_utc,f.last_error,(SELECT COUNT(*) FROM articles a WHERE a.feed_id=f.id) AS article_count FROM feeds f {condition} ORDER BY f.title COLLATE NOCASE");
    }
}
