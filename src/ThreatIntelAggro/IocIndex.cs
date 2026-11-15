using System.Text.Json;

namespace ThreatIntelAggro;

public sealed record IocRecord(
    string Type, string Value, string? NormalizedValue, string Role, string Context,
    string Confidence, string Basis, string ArticleId, string ArticleTitle,
    string ArticleUrl, string ArticleDate, string[] Vendors, string[] Industries,
    string[] Mitre, bool Approved, DateTimeOffset? ExpiresUtc, string? OriginalRole = null);

public static class IocIndex
{
    public static IReadOnlyList<IocRecord> Read(AppDatabase database, int? days = null,
        string? vendor = null, string? industry = null, string? type = null, string? search = null, bool archived = false, bool includeUnapproved = false, bool includeNonActionable = false, string? classification = null)
    {
        var args = new List<object?>();
        var dateFilter = "";
        if (days is > 0)
        {
            dateFilter = "AND COALESCE(a.published_utc,a.first_seen_utc) >= ?";
            args.Add(DateTimeOffset.UtcNow.AddDays(-days.Value).ToString("O"));
        }
        var articles = database.Query($"SELECT a.id,a.title,a.url,a.published_utc,a.first_seen_utc,a.analysis_json FROM articles a WHERE a.analysis_json IS NOT NULL {dateFilter} ORDER BY COALESCE(a.published_utc,a.first_seen_utc) DESC", args.ToArray());
        var records = new List<IocRecord>();
        var exclusions = IocExclusionMatcher.Load(database);
        var dismissed = database.Query("SELECT article_id,ioc_type,ioc_value FROM ioc_dismissals")
            .Select(row => DismissalKey(row["article_id"] ?? "", row["ioc_type"] ?? "", row["ioc_value"] ?? ""))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var approved = database.Query("SELECT article_id,ioc_type,ioc_value FROM ioc_approvals")
            .Select(row => DismissalKey(row["article_id"] ?? "", row["ioc_type"] ?? "", row["ioc_value"] ?? ""))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var roleOverrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in database.Query("SELECT article_id,ioc_type,ioc_value,role FROM ioc_role_overrides"))
            roleOverrides[DismissalKey(row["article_id"] ?? "", row["ioc_type"] ?? "", row["ioc_value"] ?? "")] = row["role"] ?? "";
        var approvalDays = ExpirySettings.Read(database);
        foreach (var article in articles)
        {
            try
            {
                using var document = JsonDocument.Parse(article["analysis_json"]!);
                var root = document.RootElement;
                var vendors = Values(root, "vendors");
                var industries = Values(root, "industries");
                var mitre = Values(root, "mitre_mappings");
                if (!root.TryGetProperty("iocs", out var iocs) || iocs.ValueKind != JsonValueKind.Array) continue;
                foreach (var ioc in iocs.EnumerateArray())
                {
                    var value = Text(ioc, "value");
                    if (string.IsNullOrWhiteSpace(value)) continue;
                    var normalizedValue = NullableText(ioc, "normalized_value");
                    if (exclusions.Excludes(Text(ioc, "type"), value, normalizedValue)) continue;
                    if (dismissed.Contains(DismissalKey(article["id"]!, Text(ioc, "type"), value)) != archived) continue;
                    var typeName = Text(ioc, "type");
                    var key = DismissalKey(article["id"]!, typeName, value);
                    var originalRole = Text(ioc, "role");
                    var overridden = roleOverrides.TryGetValue(key, out var overrideRole);
                    var effectiveRole = overridden ? overrideRole! : originalRole;
                    if ((!includeNonActionable && !IsActionableRole(effectiveRole)) || !MatchesClassification(effectiveRole, classification)) continue;
                    var isApproved = approved.Contains(key);
                    if (!includeUnapproved && !isApproved) continue;
                    var articleDate = article["published_utc"] ?? article["first_seen_utc"] ?? "";
                    var expiryDays = ExpirySettings.ForType(typeName, approvalDays);
                    DateTimeOffset? expiresUtc = DateTimeOffset.TryParse(articleDate, out var observed) && expiryDays > 0 ? observed.AddDays(expiryDays) : null;
                    if (expiresUtc is not null && expiresUtc <= DateTimeOffset.UtcNow) continue;
                    var record = new IocRecord(typeName, value, normalizedValue, effectiveRole, Text(ioc, "context"), Text(ioc, "confidence"), Text(ioc, "basis"), article["id"]!, article["title"] ?? "", article["url"] ?? "", articleDate, vendors, industries, mitre, isApproved, expiresUtc, overridden ? originalRole : null);
                    if (!Contains(vendors, vendor) || !Contains(industries, industry) || (!string.IsNullOrWhiteSpace(type) && !record.Type.Equals(type, StringComparison.OrdinalIgnoreCase))) continue;
                    if (!string.IsNullOrWhiteSpace(search) && !string.Join(' ', record.Type, record.Value, record.NormalizedValue, record.Role, record.Context, record.ArticleTitle, string.Join(' ', vendors), string.Join(' ', industries), string.Join(' ', mitre)).Contains(search, StringComparison.OrdinalIgnoreCase)) continue;
                    records.Add(record);
                }
            }
            catch (JsonException) { }
        }
        return records;
    }

    public static bool IsActionableRole(string? role) => role?.Trim().Equals("malicious", StringComparison.OrdinalIgnoreCase) == true || role?.Trim().Equals("suspicious", StringComparison.OrdinalIgnoreCase) == true;

    public static bool MatchesClassification(string? role, string? classification) => classification?.Trim().ToLowerInvariant() switch
    {
        null or "" or "all" => true,
        "context" => !IsActionableRole(role),
        "suspicious" => role?.Trim().Equals("suspicious", StringComparison.OrdinalIgnoreCase) == true,
        "malicious" => role?.Trim().Equals("malicious", StringComparison.OrdinalIgnoreCase) == true,
        _ => false
    };

    public static string DismissalKey(string articleId, string type, string value) => $"{articleId}\u001f{type}\u001f{value}";

    public static void Approve(AppDatabase database, long articleId, string type, string value) =>
        database.Execute("INSERT OR IGNORE INTO ioc_approvals(article_id,ioc_type,ioc_value,approved_utc) VALUES(?,?,?,?)", articleId, type, value, DateTimeOffset.UtcNow.ToString("O"));

    public static bool SetReviewedRole(AppDatabase database, long articleId, string? type, string? value, string? role)
    {
        if (role is not ("malicious" or "suspicious") || string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(value)) return false;
        var json = database.Query("SELECT analysis_json FROM articles WHERE id=?", articleId).FirstOrDefault()?.GetValueOrDefault("analysis_json");
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("iocs", out var list) || list.ValueKind != JsonValueKind.Array) return false;
            foreach (var item in list.EnumerateArray())
            {
                var actualType = Text(item, "type");
                var actualValue = Text(item, "value");
                if (!actualType.Equals(type, StringComparison.Ordinal) || !actualValue.Equals(value, StringComparison.Ordinal)) continue;
                database.Execute("INSERT INTO ioc_role_overrides(article_id,ioc_type,ioc_value,role,updated_utc) VALUES(?,?,?,?,?) ON CONFLICT(article_id,ioc_type,ioc_value) DO UPDATE SET role=excluded.role,updated_utc=excluded.updated_utc", articleId, actualType, actualValue, role, DateTimeOffset.UtcNow.ToString("O"));
                return true;
            }
        }
        catch (JsonException) { }
        return false;
    }

    public static void ResetReviewedRole(AppDatabase database, long articleId, string type, string value) =>
        database.Execute("DELETE FROM ioc_role_overrides WHERE article_id=? AND ioc_type=? AND ioc_value=?", articleId, type, value);

    public static void ApproveArticle(AppDatabase database, long articleId, string? analysisJson)
    {
        if (string.IsNullOrWhiteSpace(analysisJson)) return;
        try
        {
            using var document = JsonDocument.Parse(analysisJson);
            if (!document.RootElement.TryGetProperty("iocs", out var iocs) || iocs.ValueKind != JsonValueKind.Array) return;
            foreach (var ioc in iocs.EnumerateArray())
            {
                var type = Text(ioc, "type");
                var value = Text(ioc, "value");
                if (Text(ioc, "role") is "malicious" or "suspicious" && !string.IsNullOrWhiteSpace(type) && !string.IsNullOrWhiteSpace(value)) Approve(database, articleId, type, value);
            }
        }
        catch (JsonException) { }
    }

    public static string[] IocValues(AppDatabase database, JsonElement root, string? articleId = null)
    {
        if (!root.TryGetProperty("iocs", out var iocs) || iocs.ValueKind != JsonValueKind.Array) return [];
        var exclusions = IocExclusionMatcher.Load(database);
        var dismissed = string.IsNullOrWhiteSpace(articleId) ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : database.Query("SELECT ioc_type,ioc_value FROM ioc_dismissals WHERE article_id=?", articleId).Select(row => DismissalKey(articleId, row["ioc_type"] ?? "", row["ioc_value"] ?? "")).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return iocs.EnumerateArray()
            .Where(ioc => !exclusions.Excludes(Text(ioc, "type"), Text(ioc, "value"), NullableText(ioc, "normalized_value")) && !dismissed.Contains(DismissalKey(articleId ?? "", Text(ioc, "type"), Text(ioc, "value"))))
            .Select(ioc => Text(ioc, "value"))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static string[] Options(AppDatabase database, string field)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var article in database.Query("SELECT analysis_json FROM articles WHERE analysis_json IS NOT NULL"))
        {
            try
            {
                using var document = JsonDocument.Parse(article["analysis_json"]!);
                foreach (var value in Values(document.RootElement, field)) values.Add(value);
            }
            catch (JsonException) { }
        }
        return values.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static string[] Values(JsonElement root, string field)
    {
        if (!root.TryGetProperty(field, out var array) || array.ValueKind != JsonValueKind.Array) return [];
        var values = array.EnumerateArray()
            .Select(x => Text(x, "name") is { Length: > 0 } name ? name : Text(x, "value") is { Length: > 0 } value ? value : Text(x, "id"))
            .Where(x => !string.IsNullOrWhiteSpace(x));
        if (field.Equals("industries", StringComparison.OrdinalIgnoreCase))
            values = values.SelectMany(SplitIndustryList);
        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IEnumerable<string> SplitIndustryList(string value)
    {
        // Some model responses group a whole victim-sector list into one mapping.
        // Split those list-like names so facets and result tags are distinct sectors.
        if (!value.Contains(',')) return [value.Trim()];
        return value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => part.StartsWith("and ", StringComparison.OrdinalIgnoreCase) ? part[4..].Trim() : part)
            .Where(part => part.Length > 0);
    }

    private static string Text(JsonElement element, string property) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
    private static string? NullableText(JsonElement element, string property) => Text(element, property) is { Length: > 0 } value ? value : null;
    private static bool Contains(string[] values, string? selection) => string.IsNullOrWhiteSpace(selection) || values.Any(x => x.Equals(selection, StringComparison.OrdinalIgnoreCase));
}

public sealed record IocExpiryDays(int Ip, int Domain, int Hash, int Url, int Email, int SoftwareId, int FileArtifact, int HostArtifact, int Certificate, int Other);

public static class ExpirySettings
{
    public const int DefaultIpDays = 90;
    public const int DefaultDomainDays = 365;
    public const int DefaultHashDays = 365;
    public const int DefaultUrlDays = 90;
    public const int DefaultEmailDays = 365;
    public const int DefaultSoftwareIdDays = 365;
    public const int DefaultFileArtifactDays = 365;
    public const int DefaultHostArtifactDays = 365;
    public const int DefaultCertificateDays = 730;
    public const int DefaultOtherDays = 365;

    public static IocExpiryDays ReadDefaults() => new(DefaultIpDays, DefaultDomainDays, DefaultHashDays, DefaultUrlDays, DefaultEmailDays, DefaultSoftwareIdDays, DefaultFileArtifactDays, DefaultHostArtifactDays, DefaultCertificateDays, DefaultOtherDays);

    public static IocExpiryDays Read(AppDatabase database) => new(
        Get(database, "ioc_expiry_ip_days", DefaultIpDays),
        Get(database, "ioc_expiry_domain_days", DefaultDomainDays),
        Get(database, "ioc_expiry_hash_days", DefaultHashDays),
        Get(database, "ioc_expiry_url_days", DefaultUrlDays),
        Get(database, "ioc_expiry_email_days", DefaultEmailDays),
        Get(database, "ioc_expiry_software_id_days", DefaultSoftwareIdDays),
        Get(database, "ioc_expiry_file_artifact_days", DefaultFileArtifactDays),
        Get(database, "ioc_expiry_host_artifact_days", DefaultHostArtifactDays),
        Get(database, "ioc_expiry_certificate_days", DefaultCertificateDays),
        Get(database, "ioc_expiry_other_days", DefaultOtherDays));

    public static int ForType(string type, IocExpiryDays settings)
    {
        var normalized = type.Replace("-", "_", StringComparison.Ordinal).ToLowerInvariant();
        if (normalized.Contains("ipv4") || normalized.Contains("ipv6") || normalized == "ip" || normalized.Contains("ip_address") || normalized.Contains("ip_range")) return settings.Ip;
        if (normalized.Contains("domain")) return settings.Domain;
        if (normalized.Contains("hash") || normalized is "md5" or "sha1" or "sha256" or "sha512") return settings.Hash;
        if (normalized.Contains("url") || normalized.Contains("uri")) return settings.Url;
        if (normalized.Contains("email") || normalized.Contains("mailbox")) return settings.Email;
        if (normalized.Contains("browser_extension") || normalized.Contains("extension_id") || normalized.Contains("software_id")) return settings.SoftwareId;
        if (normalized.Contains("file") || normalized.Contains("path_pattern") || normalized == "path") return settings.FileArtifact;
        if (normalized.Contains("certificate") || normalized.Contains("thumbprint") || normalized.Contains("x509")) return settings.Certificate;
        if (normalized.Contains("registry") || normalized.Contains("mutex") || normalized.Contains("rpc") || normalized.Contains("named_pipe") || normalized.Contains("service_name")) return settings.HostArtifact;
        return settings.Other;
    }

    private static int Get(AppDatabase database, string key, int fallback) =>
        int.TryParse(IocExclusionSettings.Get(database, key), out var value) ? Math.Clamp(value, 0, 3650) : fallback;
}
