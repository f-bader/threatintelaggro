using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;
using System.Xml;

namespace ThreatIntelAggro;

public sealed class FeedReader(HttpClient http, AppDatabase database, ILogger<FeedReader> log)
{
    public async Task<int> RefreshAsync(long feedId, CancellationToken cancellationToken = default)
    {
        var feed = database.Query("SELECT id,title,url,interval_hours FROM feeds WHERE id=? AND enabled=1", feedId).FirstOrDefault();
        if (feed is null) return 0;
        var url = feed["url"]!;
        try
        {
            await ValidatePublicUrlAsync(url, cancellationToken);
            using var response = await GetFeedResponseAsync(url, cancellationToken);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var bounded = new MemoryStream();
            var buffer = new byte[16 * 1024];
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                if (bounded.Length + read > 10 * 1024 * 1024) throw new InvalidOperationException("Feed exceeds the 10 MB size limit.");
                bounded.Write(buffer, 0, read);
            }
            bounded.Position = 0;
            using var reader = XmlReader.Create(bounded, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 10_000_000 });
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
                var itemUrl = (string?)linkNode?.Attribute("href") ?? Text(linkNode) ?? Text(item.Elements().FirstOrDefault(x => x.Name.LocalName is "guid" or "id")) ?? "";
                if (!Uri.TryCreate(itemUrl, UriKind.Absolute, out var articleUri) || articleUri.Scheme is not ("https" or "http")) continue;
                var dateText = Text(item.Elements().FirstOrDefault(x => x.Name.LocalName is "pubDate" or "published" or "updated" or "date"));
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
            log.LogWarning("Feed {FeedId} refresh failed: {Error}", feedId, message);
            throw;
        }
    }

    private static string Limit(string value, int max) => value.Length <= max ? value : value[..max];

    private static string? Text(XElement? element) => element is null ? null : (element.HasElements ? string.Concat(element.DescendantNodes().OfType<XText>().Select(x => x.Value)) : element.Value).Trim();

    private async Task<HttpResponseMessage> GetFeedResponseAsync(string address, CancellationToken cancellationToken)
    {
        var current = new Uri(address);
        for (var hop = 0; hop <= 5; hop++)
        {
            await ValidatePublicUrlAsync(current.ToString(), cancellationToken);
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is not null)
            {
                var destination = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(current, response.Headers.Location);
                response.Dispose();
                current = destination;
                continue;
            }
            return response;
        }
        throw new InvalidOperationException("Feed redirect limit exceeded.");
    }

    private static async Task ValidatePublicUrlAsync(string address, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidOperationException("Enter a valid public HTTP or HTTPS feed URL.");
        if (IPAddress.TryParse(uri.Host, out var direct))
        {
            if (!IsPublic(direct)) throw new InvalidOperationException("Private and local network feed addresses are blocked.");
            return;
        }
        var addresses = await Dns.GetHostAddressesAsync(uri.DnsSafeHost, cancellationToken);
        if (addresses.Length == 0 || addresses.Any(address => !IsPublic(address)))
            throw new InvalidOperationException("The feed host resolves to a private or local network address.");
    }

    private static bool IsPublic(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
        var bytes = ip.MapToIPv6().GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var v4 = ip.GetAddressBytes();
            return !(v4[0] == 10 || v4[0] == 127 || (v4[0] == 169 && v4[1] == 254) || (v4[0] == 172 && v4[1] is >= 16 and <= 31) || (v4[0] == 192 && v4[1] == 168) || v4[0] == 0);
        }
        return !(bytes[0] == 0xfc || bytes[0] == 0xfd || bytes[0] == 0xff);
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
