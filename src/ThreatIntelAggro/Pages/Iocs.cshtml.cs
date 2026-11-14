using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro.Pages;

public sealed class IocsModel(AppDatabase database) : PageModel
{
    public IReadOnlyList<IocRecord> Records { get; private set; } = [];
    public string[] Vendors { get; private set; } = [];
    public string[] Industries { get; private set; } = [];
    public string[] Types { get; private set; } = [];
    public string ApiExampleUrl { get; private set; } = "/api/iocs?days=30";
    public IocExpiryDays ExpiryDays { get; private set; } = ExpirySettings.ReadDefaults();
    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 30;
    [BindProperty(SupportsGet = true)] public string? Vendor { get; set; }
    [BindProperty(SupportsGet = true)] public string? Industry { get; set; }
    [BindProperty(SupportsGet = true)] public string? Type { get; set; }
    [BindProperty(SupportsGet = true)] public string? Search { get; set; }
    [BindProperty(SupportsGet = true)] public string State { get; set; } = "active";
    [BindProperty(SupportsGet = true)] public string Approval { get; set; } = "all";
    [BindProperty(SupportsGet = true)] public bool IncludeUnapproved { get; set; }

    public void OnGet() => Load();

    public IActionResult OnGetCsv()
    {
        Load();
        var builder = new StringBuilder("type,value,normalized_value,approval,expires_utc,role,context,confidence,basis,article_title,article_url,article_date,vendors,industries,mitre\r\n");
        foreach (var ioc in Records)
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
        ExpiryDays = ExpirySettings.Read(database);
        var archived = State == "archived";
        var visible = IocIndex.Read(database, Days, archived: archived, includeUnapproved: true);
        Vendors = FacetValues(visible.Where(x => MatchesApproval(x) && Contains(x.Industries, Industry) && Matches(x.Type, Type) && MatchesSearch(x, Search)).SelectMany(x => x.Vendors));
        Industries = FacetValues(visible.Where(x => MatchesApproval(x) && Contains(x.Vendors, Vendor) && Matches(x.Type, Type) && MatchesSearch(x, Search)).SelectMany(x => x.Industries));
        Types = FacetValues(visible.Where(x => MatchesApproval(x) && Contains(x.Vendors, Vendor) && Contains(x.Industries, Industry) && MatchesSearch(x, Search)).Select(x => x.Type));
        Records = visible.Where(x => MatchesApproval(x) && Contains(x.Vendors, Vendor) && Contains(x.Industries, Industry) && Matches(x.Type, Type) && MatchesSearch(x, Search)).ToArray();
        var apiFilters = new Dictionary<string, string?>
        {
            ["days"] = Days.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["type"] = Type,
            ["vendor"] = Vendor,
            ["industry"] = Industry,
            ["search"] = Search,
            ["includeUnapproved"] = IncludeUnapproved ? "true" : null
        }.Where(x => !string.IsNullOrWhiteSpace(x.Value));
        ApiExampleUrl = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString("/api/iocs", apiFilters);
    }

    public IActionResult OnPostApprove(long articleId, string iocType, string iocValue) => SaveApproval(articleId, iocType, iocValue);
    public IActionResult OnPostDismiss(long articleId, string iocType, string iocValue) => ChangeArchive(articleId, iocType, iocValue, true);
    public IActionResult OnPostRestore(long articleId, string iocType, string iocValue) => ChangeArchive(articleId, iocType, iocValue, false);

    private IActionResult SaveApproval(long articleId, string iocType, string iocValue)
    {
        IocIndex.Approve(database, articleId, iocType, iocValue);
        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, includeUnapproved = IncludeUnapproved });
    }

    private IActionResult ChangeArchive(long articleId, string iocType, string iocValue, bool archive)
    {
        if (archive)
            database.Execute("INSERT OR IGNORE INTO ioc_dismissals(article_id,ioc_type,ioc_value,dismissed_utc) VALUES(?,?,?,?)", articleId, iocType, iocValue, DateTimeOffset.UtcNow.ToString("O"));
        else
            database.Execute("DELETE FROM ioc_dismissals WHERE article_id=? AND ioc_type=? AND ioc_value=?", articleId, iocType, iocValue);
        return RedirectToPage(new { days = Days, vendor = Vendor, industry = Industry, type = Type, search = Search, state = State, approval = Approval, includeUnapproved = IncludeUnapproved });
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

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";
}
