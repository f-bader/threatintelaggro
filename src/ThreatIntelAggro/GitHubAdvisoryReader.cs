using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public sealed class GitHubAdvisoryReader(HttpClient client)
{
    private static readonly TimeSpan InitialWindow = TimeSpan.FromDays(14);

    public async Task<int> RefreshAsync(AppDatabase database, long feedId, string feedTitle, string repositoryUrl, CancellationToken cancellationToken)
    {
        if (!TryGetRepository(repositoryUrl, out var owner, out var repository))
            throw new InvalidOperationException("GitHub source URL is not a valid public repository URL.");

        var cutoff = DateTimeOffset.UtcNow - InitialWindow;
        var requestUrl = $"https://api.github.com/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/security-advisories?state=published&sort=published&direction=desc&per_page=100";
        var added = 0;
        var pageCount = 0;
        while (!string.IsNullOrWhiteSpace(requestUrl))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (++pageCount > 20) throw new InvalidOperationException("GitHub returned too many advisory pages for one refresh.");
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2026-03-10");
            request.Headers.UserAgent.ParseAdd("ThreatIntelAggro/0.1");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var detail = await response.Content.ReadAsStringAsync(cancellationToken);
                if (detail.Length > 500) detail = detail[..500];
                throw new HttpRequestException($"GitHub returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.{(detail.Length > 0 ? " " + detail : "")}", null, response.StatusCode);
            }

            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var json = await JsonDocument.ParseAsync(body, new JsonDocumentOptions { MaxDepth = 48 }, cancellationToken);
            if (json.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("GitHub returned an invalid advisory response.");
            var reachedOlderAdvisory = false;
            foreach (var advisory in json.RootElement.EnumerateArray())
            {
                var published = ReadDate(advisory, "published_at");
                if (published is null || published < cutoff) { reachedOlderAdvisory = true; continue; }
                var ghsa = ReadString(advisory, "ghsa_id");
                if (string.IsNullOrWhiteSpace(ghsa) || !Regex.IsMatch(ghsa, "^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$", RegexOptions.CultureInvariant)) continue;
                var summary = BuildSummary(advisory);
                var title = ReadString(advisory, "summary");
                if (string.IsNullOrWhiteSpace(title)) title = ghsa;
                if (title.Length > 500) title = title[..500];
                var articleUrl = $"https://github.com/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/security/advisories/{ghsa}";
                var publishedText = published.Value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
                added += database.Execute("INSERT OR IGNORE INTO articles(feed_id,feed_title,title,url,summary,published_utc,first_seen_utc) VALUES(?,?,?,?,?,?,?)",
                    feedId, feedTitle, title, articleUrl, summary, publishedText, DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            }
            if (reachedOlderAdvisory) break;
            requestUrl = NextLink(response.Headers);
        }
        return added;
    }

    private static string BuildSummary(JsonElement advisory)
    {
        var output = new StringBuilder();
        Append("Summary", ReadString(advisory, "summary"));
        Append("Description", ReadString(advisory, "description"));
        Append("Severity", ReadString(advisory, "severity"));
        Append("GHSA", ReadString(advisory, "ghsa_id"));
        Append("CVE", ReadString(advisory, "cve_id"));

        if (advisory.TryGetProperty("vulnerabilities", out var vulnerabilities) && vulnerabilities.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in vulnerabilities.EnumerateArray().Take(50))
            {
                var package = item.TryGetProperty("package", out var value) ? value : default;
                var ecosystem = ReadString(package, "ecosystem");
                var name = ReadString(package, "name");
                var range = ReadString(item, "vulnerable_version_range");
                var patched = ReadString(item, "first_patched_version") ?? ReadString(item, "patched_versions");
                var line = string.Join(" ", new[] { ecosystem, name, range is null ? null : $"affected: {range}", patched is null ? null : $"patched: {patched}" }.Where(x => !string.IsNullOrWhiteSpace(x)));
                if (line.Length > 0) Append("Affected package", line);
            }
        }
        return output.ToString();

        void Append(string label, string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || output.Length >= 5000) return;
            var line = $"{label}: {value.Trim()}";
            var separatorLength = output.Length > 0 ? 1 : 0;
            var room = 5000 - output.Length - separatorLength;
            if (room <= 0) return;
            if (line.Length > room) line = line[..room];
            if (separatorLength > 0) output.Append('\n');
            output.Append(line);
        }
    }

    private static string? NextLink(HttpResponseHeaders headers)
    {
        if (!headers.TryGetValues("Link", out var values)) return null;
        foreach (var part in string.Join(",", values).Split(','))
        {
            var match = Regex.Match(part.Trim(), "^<(?<url>[^>]+)>\\s*;\\s*rel=\"next\"", RegexOptions.CultureInvariant);
            if (match.Success && Uri.TryCreate(match.Groups["url"].Value, UriKind.Absolute, out var uri) &&
                uri.Scheme == Uri.UriSchemeHttps && uri.Host.Equals("api.github.com", StringComparison.OrdinalIgnoreCase)) return uri.ToString();
        }
        return null;
    }

    private static bool TryGetRepository(string url, out string owner, out string repository)
    {
        owner = repository = "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        var parts = uri.AbsolutePath.Trim('/').Split('/');
        if (parts.Length != 2 || !Regex.IsMatch(parts[0], "^[A-Za-z0-9-]+$", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(parts[1], "^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant) || parts[1] is "." or ".." || parts[1].EndsWith(".git", StringComparison.OrdinalIgnoreCase)) return false;
        owner = parts[0]; repository = parts[1];
        return true;
    }

    private static string? ReadString(JsonElement element, string property) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static DateTimeOffset? ReadDate(JsonElement element, string property) => DateTimeOffset.TryParse(ReadString(element, property), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date) ? date : null;
}
