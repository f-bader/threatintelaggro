using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace ThreatIntelAggro.Pages;

public sealed class IocsModel(AppDatabase database) : PageModel
{
    public IReadOnlyList<IocRecord> Records { get; private set; } = [];
    public string[] Vendors { get; private set; } = [];
    public string[] Industries { get; private set; } = [];
    public string[] Types { get; private set; } = [];
    public string[] Classifications { get; private set; } = [];
    public string ApiExampleUrl { get; private set; } = "/api/iocs?days=30";
    public IocExpiryDays ExpiryDays { get; private set; } = ExpirySettings.ReadDefaults();
    public int TotalInRange { get; private set; }
    public int ArchivedCount { get; private set; }
    public int ExcludedCount { get; private set; }
    public int ExpiredCount { get; private set; }
    public int ContextCount { get; private set; }
    public int PendingCount { get; private set; }
    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 30;
    [BindProperty(SupportsGet = true)] public string? Vendor { get; set; }
    [BindProperty(SupportsGet = true)] public string? Industry { get; set; }
    [BindProperty(SupportsGet = true)] public string? Type { get; set; }
    [BindProperty(SupportsGet = true)] public string? Search { get; set; }
    [BindProperty(SupportsGet = true)] public string State { get; set; } = "active";
    [BindProperty(SupportsGet = true)] public string Approval { get; set; } = "all";
    [BindProperty(SupportsGet = true)] public string Classification { get; set; } = "all";
    [BindProperty(SupportsGet = true)] public bool IncludeUnapproved { get; set; }

    public void OnGet() => Load();

    public IActionResult OnGetCsv()
    {
        Load();
        var builder = new StringBuilder("type,value,normalized_value,approval,expires_utc,role,context,confidence,basis,article_title,article_url,article_date,vendors,industries,mitre\r\n");
        foreach (var ioc in Records.Where(ioc => IocIndex.IsActionableRole(ioc.Role)))
        {
            var row = new[] { ioc.Type, ioc.Value, ioc.NormalizedValue ?? "", ioc.Approved ? "approved" : "unapproved", ioc.ExpiresUtc?.ToString("O") ?? "", ioc.Role, ioc.Context, ioc.Confidence, ioc.Basis, ioc.ArticleTitle, ioc.ArticleUrl, ioc.ArticleDate, string.Join("; ", ioc.Vendors), string.Join("; ", ioc.Industries), string.Join("; ", ioc.Mitre) };
            builder.AppendJoin(',', row.Select(Csv)).Append("\r\n");
        }
        return File(Encoding.UTF8.GetBytes(builder.ToString()), "text/csv; charset=utf-8", $"threat-intel-aggro-iocs-{Days}d.csv");
    }

    private void Load()
    {
        Days = Math.Clamp(Days, 1, 3650);
        State = State == "archived" ? "archived" : "active";
        Approval = Approval is "approved" or "pending" ? Approval : "all";
        Classification = Classification is "suspicious" or "malicious" or "context" ? Classification : "all";
        ExpiryDays = ExpirySettings.Read(database);
        var archived = State == "archived";
        var all = IocIndex.Read(database, Days, includeUnapproved: true, includeNonActionable: true, includeFiltered: true);
        TotalInRange = all.Count;
        ArchivedCount = all.Count(x => x.Archived);
        ExcludedCount = all.Count(x => x.Excluded);
        ExpiredCount = all.Count(x => x.Expired);
        ContextCount = all.Count(x => !IocIndex.IsActionableRole(x.Role));
        PendingCount = all.Count(x => !x.Approved);
        var visible = all.Where(x => !x.Excluded && !x.Expired && x.Archived == archived).ToArray();
        Classifications = new[] { "malicious", "suspicious", "context" }.Where(c => c == Classification || visible.Any(x => IocIndex.MatchesClassification(x.Role, c) && MatchesApproval(x) && Contains(x.Vendors, Vendor) && Contains(x.Industries, Industry) && Matches(x.Type, Type) && MatchesSearch(x, Search))).ToArray();
        Vendors = FacetValues(visible.Where(x => IocIndex.MatchesClassification(x.Role, Classification) && MatchesApproval(x) && Contains(x.Industries, Industry) && Matches(x.Type, Type) && MatchesSearch(x, Search)).SelectMany(x => x.Vendors));
        Industries = FacetValues(visible.Where(x => IocIndex.MatchesClassification(x.Role, Classification) && MatchesApproval(x) && Contains(x.Vendors, Vendor) && Matches(x.Type, Type) && MatchesSearch(x, Search)).SelectMany(x => x.Industries));
        Types = FacetValues(visible.Where(x => IocIndex.MatchesClassification(x.Role, Classification) && MatchesApproval(x) && Contains(x.Vendors, Vendor) && Contains(x.Industries, Industry) && MatchesSearch(x, Search)).Select(x => x.Type));
        Records = visible.Where(x => IocIndex.MatchesClassification(x.Role, Classification) && MatchesApproval(x) && Contains(x.Vendors, Vendor) && Contains(x.Industries, Industry) && Matches(x.Type, Type) && MatchesSearch(x, Search)).ToArray();
        var apiFilters = new Dictionary<string, string?>
        {
            ["days"] = Days.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["type"] = Type,
            ["vendor"] = Vendor,
            ["industry"] = Industry,
            ["search"] = Search,
            ["classification"] = Classification == "all" ? null : Classification,
            ["includeUnapproved"] = IncludeUnapproved ? "true" : null
        }.Where(x => !string.IsNullOrWhiteSpace(x.Value));
        ApiExampleUrl = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString("/api/iocs", apiFilters);
    }

    public IActionResult OnPostApprove(long articleId, string iocType, string iocValue) => SaveApproval(articleId, iocType, iocValue);
    public IActionResult OnPostDismiss(long articleId, string iocType, string iocValue) => ChangeArchive(articleId, iocType, iocValue, true);
    public IActionResult OnPostRestore(long articleId, string iocType, string iocValue) => ChangeArchive(articleId, iocType, iocValue, false);

    public IActionResult OnPostClassify(long articleId, string iocType, string iocValue, string? role)
    {
        if (!IocIndex.SetReviewedRole(database, articleId, iocType, iocValue, role)) return BadRequest("Invalid indicator or classification.");
        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, classification = Classification, includeUnapproved = IncludeUnapproved });
    }

    private sealed record BulkIndicator(long ArticleId, string Type, string Value);
    public static string BulkToken(IocRecord record) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new BulkIndicator(long.Parse(record.ArticleId, System.Globalization.CultureInfo.InvariantCulture), record.Type, record.Value)));

    public IActionResult OnPostBulkReview(string[]? selection, string? operation, string? bulkRole) => ApplyBulkReview(selection, operation, bulkRole);

    public IActionResult OnPostBulkClassify(string[]? selection, string? bulkRole) => ApplyBulkReview(selection, "classify", bulkRole);

    private IActionResult ApplyBulkReview(string[]? selection, string? operation, string? bulkRole)
    {
        if (selection is null || selection.Length is < 1 or > 500) return BadRequest("Select 1–500 indicators.");
        if (operation is not ("classify" or "approve" or "dismiss")) return BadRequest("Choose a valid bulk action.");
        if (operation == "classify" && bulkRole is not ("malicious" or "suspicious")) return BadRequest("Choose a classification.");

        var selected = new List<BulkIndicator>();
        try
        {
            foreach (var token in selection)
            {
                if (token.Length > 4096) return BadRequest("Invalid selection.");
                var item = JsonSerializer.Deserialize<BulkIndicator>(Convert.FromBase64String(token));
                if (item is null || item.ArticleId <= 0 || string.IsNullOrWhiteSpace(item.Type) || string.IsNullOrWhiteSpace(item.Value)) return BadRequest("Invalid selection.");
                selected.Add(item);
            }
        }
        catch (Exception ex) when (ex is FormatException or JsonException) { return BadRequest("Invalid selection."); }

        try
        {
            database.Transaction(() =>
            {
                string Key(IocRecord ioc) => IocIndex.DismissalKey(ioc.ArticleId, ioc.Type, ioc.Value);
                var current = IocIndex.Read(database, includeUnapproved: true, includeNonActionable: true)
                    .GroupBy(Key, StringComparer.Ordinal)
                    .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
                var now = DateTimeOffset.UtcNow.ToString("O");
                foreach (var item in selected)
                {
                    var key = IocIndex.DismissalKey(item.ArticleId.ToString(System.Globalization.CultureInfo.InvariantCulture), item.Type, item.Value);
                    if (!current.Remove(key, out var ioc)) throw new InvalidOperationException("A selected indicator is no longer available for this action.");
                    var actionable = IocIndex.IsActionableRole(ioc.Role);
                    switch (operation)
                    {
                        case "classify":
                            if (actionable || !IocIndex.SetReviewedRole(database, item.ArticleId, item.Type, item.Value, bulkRole))
                                throw new InvalidOperationException("Classification applies only to selected context-only indicators.");
                            break;
                        case "approve":
                            if (!actionable || ioc.Approved) throw new InvalidOperationException("Approval applies only to selected, unapproved suspicious or malicious indicators.");
                            IocIndex.Approve(database, item.ArticleId, item.Type, item.Value);
                            break;
                        case "dismiss":
                            database.Execute("INSERT OR IGNORE INTO ioc_dismissals(article_id,ioc_type,ioc_value,dismissed_utc) VALUES(?,?,?,?)", item.ArticleId, item.Type, item.Value, now);
                            break;
                    }
                }
            });
        }
        catch (InvalidOperationException ex) { return BadRequest(ex.Message); }

        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, classification = Classification, includeUnapproved = IncludeUnapproved });
    }

    public IActionResult OnPostResetClassification(long articleId, string iocType, string iocValue)
    {
        IocIndex.ResetReviewedRole(database, articleId, iocType, iocValue);
        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, classification = Classification, includeUnapproved = IncludeUnapproved });
    }

    private IActionResult SaveApproval(long articleId, string iocType, string iocValue)
    {
        IocIndex.Approve(database, articleId, iocType, iocValue);
        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, classification = Classification, includeUnapproved = IncludeUnapproved });
    }

    private IActionResult ChangeArchive(long articleId, string iocType, string iocValue, bool archive)
    {
        if (archive)
            database.Execute("INSERT OR IGNORE INTO ioc_dismissals(article_id,ioc_type,ioc_value,dismissed_utc) VALUES(?,?,?,?)", articleId, iocType, iocValue, DateTimeOffset.UtcNow.ToString("O"));
        else
            database.Execute("DELETE FROM ioc_dismissals WHERE article_id=? AND ioc_type=? AND ioc_value=?", articleId, iocType, iocValue);
        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, classification = Classification, includeUnapproved = IncludeUnapproved });
    }

    public string? VirusTotalUrl(IocRecord ioc)
    {
        var value = (ioc.NormalizedValue ?? ioc.Value).Trim();
        value = value.Replace("[.]", ".", StringComparison.OrdinalIgnoreCase).Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase).Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase);
        var kind = ioc.Type.ToLowerInvariant();
        var hash = Regex.IsMatch(value, "^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$");
        var ip = System.Net.IPAddress.TryParse(value.Trim('[', ']'), out _);
        var uri = Uri.TryCreate(value, UriKind.Absolute, out var parsed) && (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps);
        var domain = Uri.CheckHostName(value) == UriHostNameType.Dns && value.Contains('.') && !value.Contains(' ');
        var supported = hash || (kind.Contains("domain") && domain) || (kind.Contains("ip") && ip) || (kind.Contains("url") && uri);
        return supported ? "https://www.virustotal.com/gui/search?query=" + Uri.EscapeDataString(value) : null;
    }

    private static string[] FacetValues(IEnumerable<string> values) => values
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private bool MatchesApproval(IocRecord record) => Approval switch { "approved" => record.Approved, "pending" => !record.Approved, _ => true };
    private static bool Matches(string value, string? selected) => string.IsNullOrWhiteSpace(selected) || value.Equals(selected, StringComparison.OrdinalIgnoreCase);
    private static bool Contains(IEnumerable<string> values, string? selected) => string.IsNullOrWhiteSpace(selected) || values.Any(x => x.Equals(selected, StringComparison.OrdinalIgnoreCase));
    private static bool MatchesSearch(IocRecord x, string? search) => string.IsNullOrWhiteSpace(search) || string.Join(' ', x.Type, x.Value, x.NormalizedValue, x.Role, x.Context, x.ArticleTitle, string.Join(' ', x.Vendors), string.Join(' ', x.Industries), string.Join(' ', x.Mitre)).Contains(search, StringComparison.OrdinalIgnoreCase);

    public string IndustryLabel(string value)
    {
        if (value.Length <= 38) return value;
        var sectors = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (sectors.Length > 2) return $"{sectors[0]}, {sectors[1]} + {sectors.Length - 2} more";
        return value[..35].TrimEnd() + "…";
    }

    private static string Csv(string value)
    {
        var index = 0;
        var hasControl = false;
        while (index < value.Length && (char.IsWhiteSpace(value[index]) || value[index] == '\ufeff' || char.IsControl(value[index])))
        {
            hasControl |= char.IsControl(value[index]);
            index++;
        }
        if (hasControl || (index < value.Length && "=+-@".Contains(value[index]))) value = "'" + value;
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }
}
