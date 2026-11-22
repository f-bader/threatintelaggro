using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using System.Xml;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public sealed class FeedReader(SafePublicFetcher fetcher, AppDatabase database, ILogger<FeedReader> log, GitHubAdvisoryReader? githubAdvisories = null, HomeFeedRoute? homeRoute = null)
{
    public Task<bool> CheckHomeRouteAsync(CancellationToken cancellationToken) =>
        homeRoute?.CheckAvailabilityAsync(cancellationToken) ?? Task.FromResult(false);

    public async Task<int> RefreshAsync(long feedId, CancellationToken cancellationToken = default)
    {
        var feed = database.Query("SELECT id,title,url,interval_hours,source_type,fetch_route FROM feeds WHERE id=? AND enabled=1", feedId).FirstOrDefault();
        if (feed is null) return 0;
        var url = feed["url"]!;
        try
        {
            var route = feed["fetch_route"] == "default" ? HomeFeedRoute.DefaultRoute(database) : feed["fetch_route"];
            var selectedHomeRoute = route == "home"
                ? homeRoute ?? throw new InvalidOperationException("Home exit node is not configured.")
                : null;
            if (feed.GetValueOrDefault("source_type") == "github")
            {
                var advisor = selectedHomeRoute?.CreateGitHubReader() ?? githubAdvisories
                    ?? throw new InvalidOperationException("GitHub advisory collection is not configured.");
                var count = await advisor
                    .RefreshAsync(database, feedId, feed["title"] ?? "GitHub advisories", url, cancellationToken);
                database.Execute("UPDATE feeds SET last_checked_utc=?,last_error=NULL WHERE id=?", DateTimeOffset.UtcNow.ToString("O"), feedId);
                log.LogInformation("GitHub advisory source {FeedId} refresh found {ArticleCount} new entries", feedId, count);
                return count;
            }
            var timeout = TimeSpan.FromSeconds(25);
            const int maxBytes = 10 * 1024 * 1024;
            var bytes = selectedHomeRoute is not null
                ? await selectedHomeRoute.GetAsync(url, maxBytes, timeout, cancellationToken)
                : await fetcher.GetAsync(url, maxBytes, timeout, cancellationToken);
            using var text = new StringReader(CleanXmlCharacters(DecodeXml(bytes)));
            using var reader = XmlReader.Create(text, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 10_000_000
            });
            var xml = XDocument.Load(reader);
            var feedTitle = Text(xml.Root?.Elements().FirstOrDefault(x => x.Name.LocalName == "title")) ?? feed["title"] ?? "RSS feed";
            var items = xml.Descendants().Where(x => x.Name.LocalName is "item" or "entry").Take(300).ToList();
            var now = DateTimeOffset.UtcNow;
            var earliest = now.AddDays(-14);
            var added = 0;
            foreach (var item in items)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var linkNode = item.Elements().FirstOrDefault(x => x.Name.LocalName == "link" && ((string?)x.Attribute("rel") is null or "alternate"));
                var itemUrl = CleanXmlCharacters((string?)linkNode?.Attribute("href") ?? Text(linkNode) ?? Text(item.Elements().FirstOrDefault(x => x.Name.LocalName is "guid" or "id")) ?? "");
                if (!Uri.TryCreate(itemUrl, UriKind.Absolute, out var articleUri) || articleUri.Scheme is not ("https" or "http")) continue;
                // A feed's updated timestamp can change after publication. Prefer
                // explicit publication fields regardless of their XML order.
                var dateNode = item.Elements().FirstOrDefault(x => x.Name.LocalName is "pubDate" or "published")
                    ?? item.Elements().FirstOrDefault(x => x.Name.LocalName is "updated" or "date");
                var dateText = Text(dateNode);
                var hasDate = DateTimeOffset.TryParse(dateText, out var published);
                if (hasDate && (published < earliest || published > now.AddDays(1))) continue;
                var summaryNode = item.Elements().FirstOrDefault(x => x.Name.LocalName is "encoded" or "content" or "summary" or "description");
                var summary = Text(summaryNode) ?? string.Empty;
                if (summary.Length > 5000) summary = summary[..5000];
                added += database.Execute("INSERT OR IGNORE INTO articles(feed_id,feed_title,title,url,summary,published_utc,first_seen_utc) VALUES(?,?,?,?,?,?,?)",
                    feedId, feedTitle, Limit(Text(item.Elements().FirstOrDefault(x => x.Name.LocalName == "title")) ?? itemUrl, 500), articleUri.ToString(), summary,
                    hasDate ? published.ToUniversalTime().ToString("O") : null, now.ToString("O"));
            }
            database.Execute("UPDATE feeds SET last_checked_utc=?,last_error=NULL WHERE id=?", now.ToString("O"), feedId);
            log.LogInformation("Feed {FeedId} refresh found {ArticleCount} new entries", feedId, added);
            return added;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var message = Limit(exception.Message, 500);
            database.Execute("UPDATE feeds SET last_checked_utc=?,last_error=? WHERE id=?", DateTimeOffset.UtcNow.ToString("O"), message, feedId);
            log.LogWarning(exception, "Feed {FeedId} refresh failed: {Error}", feedId, message);
            throw;
        }
    }

    private static string Limit(string value, int max) => value.Length <= max ? value : value[..max];

    private static string DecodeXml(byte[] bytes)
    {
        var encoding = Encoding.UTF8;
        var preambleLength = 0;
        if (bytes.AsSpan().StartsWith(new byte[] { 0x00, 0x00, 0xFE, 0xFF })) { encoding = new UTF32Encoding(true, true); preambleLength = 4; }
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE, 0x00, 0x00 })) { encoding = new UTF32Encoding(false, true); preambleLength = 4; }
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) { encoding = Encoding.UTF8; preambleLength = 3; }
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xFE, 0xFF })) { encoding = Encoding.BigEndianUnicode; preambleLength = 2; }
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE })) { encoding = Encoding.Unicode; preambleLength = 2; }
        else if (bytes.Length >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x3C) encoding = new UTF32Encoding(true, false);
        else if (bytes.Length >= 4 && bytes[0] == 0x3C && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x00) encoding = new UTF32Encoding(false, false);
        else if (bytes.Length >= 4 && bytes[0] == 0x00 && bytes[1] == 0x3C && bytes[2] == 0x00 && bytes[3] == 0x3F) encoding = Encoding.BigEndianUnicode;
        else if (bytes.Length >= 4 && bytes[0] == 0x3C && bytes[1] == 0x00 && bytes[2] == 0x3F && bytes[3] == 0x00) encoding = Encoding.Unicode;
        else
        {
            var declaration = Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, 512));
            var match = Regex.Match(declaration, "encoding\\s*=\\s*['\\\"](?<name>[^'\\\"]+)['\\\"]", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                try { encoding = Encoding.GetEncoding(match.Groups["name"].Value); }
                catch (ArgumentException) { }
            }
        }

        return encoding.GetString(bytes, preambleLength, bytes.Length - preambleLength);
    }

    private static string? Text(XElement? element) => element is null ? null : CleanXmlCharacters(element.HasElements ? string.Concat(element.DescendantNodes().OfType<XText>().Select(x => x.Value)) : element.Value).Trim();

    private static string CleanXmlCharacters(string value)
    {
        StringBuilder? cleaned = null;
        for (var index = 0; index < value.Length; index++)
        {
            var current = value[index];
            var valid = current is '\t' or '\n' or '\r' || current >= '\u0020' && !char.IsSurrogate(current) && current is not '\uFFFE' and not '\uFFFF';
            if (char.IsHighSurrogate(current) && index + 1 < value.Length && char.IsLowSurrogate(value[index + 1]))
            {
                if (cleaned is not null) cleaned.Append(current).Append(value[++index]);
                else index++;
                continue;
            }
            if (valid)
            {
                if (cleaned is not null) cleaned.Append(current);
                continue;
            }

            cleaned ??= new StringBuilder(value.Length).Append(value, 0, index);
        }
        return cleaned?.ToString() ?? value;
    }


}

public sealed class FeedScheduler(IServiceScopeFactory scopes, AppDatabase database, ILogger<FeedScheduler> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(4), stoppingToken);
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                var due = database.Query("SELECT id,interval_hours,last_checked_utc FROM feeds WHERE enabled=1");
                foreach (var row in due)
                {
                    if (long.TryParse(row["id"], out var id) &&
                        (!DateTimeOffset.TryParse(row["last_checked_utc"], out var lastChecked) || now - lastChecked >= TimeSpan.FromHours(int.TryParse(row["interval_hours"], out var hours) ? hours : 6)))
                    {
                        using var scope = scopes.CreateScope();
                        var reader = scope.ServiceProvider.GetRequiredService<FeedReader>();
                        try { await reader.RefreshAsync(id, stoppingToken); }
                        catch (Exception exception) when (exception is not OperationCanceledException) { log.LogDebug("Scheduled feed refresh failed for {FeedId}", id); }
                    }
                }
            }
            catch (Exception exception) { log.LogError(exception, "Feed scheduler iteration failed"); }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
