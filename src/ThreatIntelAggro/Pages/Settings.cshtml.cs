using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class SettingsModel(AppDatabase database) : PageModel
{
    public IReadOnlyList<Dictionary<string, string?>> IocExclusions { get; private set; } = [];
    public bool ExcludeM365 { get; private set; }
    public string M365RefreshedUtc { get; private set; } = "";
    public string M365RefreshError { get; private set; } = "";
    public IocExpiryDays ExpiryDays { get; private set; } = ExpirySettings.ReadDefaults();
    [BindProperty] public string IocExclusion { get; set; } = "";
    [BindProperty] public int IpExpiryDays { get; set; } = ExpirySettings.DefaultIpDays;
    [BindProperty] public int DomainExpiryDays { get; set; } = ExpirySettings.DefaultDomainDays;
    [BindProperty] public int HashExpiryDays { get; set; } = ExpirySettings.DefaultHashDays;
    [BindProperty] public int UrlExpiryDays { get; set; } = ExpirySettings.DefaultUrlDays;
    [BindProperty] public int EmailExpiryDays { get; set; } = ExpirySettings.DefaultEmailDays;
    [BindProperty] public int SoftwareIdExpiryDays { get; set; } = ExpirySettings.DefaultSoftwareIdDays;
    [BindProperty] public int FileArtifactExpiryDays { get; set; } = ExpirySettings.DefaultFileArtifactDays;
    [BindProperty] public int HostArtifactExpiryDays { get; set; } = ExpirySettings.DefaultHostArtifactDays;
    [BindProperty] public int CertificateExpiryDays { get; set; } = ExpirySettings.DefaultCertificateDays;
    [BindProperty] public int OtherExpiryDays { get; set; } = ExpirySettings.DefaultOtherDays;
    [TempData] public string? Notice { get; set; }

    public void OnGet() => Load();

    public IActionResult OnPostAddIocExclusion()
    {
        IocExclusion = IocExclusion.Trim();
        if (!IocExclusionMatcher.IsValidRule(IocExclusion))
        {
            Notice = "Enter a domain, IP address, or IP range in CIDR notation (for example, example.com or 192.0.2.0/24).";
            Load();
            return Page();
        }
        database.Execute("INSERT OR IGNORE INTO ioc_exclusions(value,created_utc) VALUES(?,?)", IocExclusion, DateTimeOffset.UtcNow.ToString("O"));
        Notice = "IOC exclusion saved. Matching indicators are hidden from IOC results, exports, and the API.";
        return RedirectToPage();
    }

    public IActionResult OnPostRemoveIocExclusion(long id)
    {
        database.Execute("DELETE FROM ioc_exclusions WHERE id=?", id);
        Notice = "IOC exclusion removed.";
        return RedirectToPage();
    }

    public IActionResult OnPostToggleM365(bool enabled)
    {
        IocExclusionSettings.Set(database, "exclude_m365_endpoints", enabled ? "true" : "false");
        Notice = enabled ? "Microsoft 365 URL and IP range exclusions enabled." : "Microsoft 365 URL and IP range exclusions disabled.";
        return RedirectToPage();
    }

    public IActionResult OnPostSaveIocExpiry()
    {
        var values = new[] { IpExpiryDays, DomainExpiryDays, HashExpiryDays, UrlExpiryDays, EmailExpiryDays, SoftwareIdExpiryDays, FileArtifactExpiryDays, HostArtifactExpiryDays, CertificateExpiryDays, OtherExpiryDays };
        if (values.Any(value => value is < 0 or > 3650))
        {
            Notice = "IOC expiry must be between 0 and 3650 days. Use 0 to keep that IOC type active indefinitely.";
            Load();
            return Page();
        }
        IocExclusionSettings.Set(database, "ioc_expiry_ip_days", IpExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_domain_days", DomainExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_hash_days", HashExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_url_days", UrlExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_email_days", EmailExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_software_id_days", SoftwareIdExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_file_artifact_days", FileArtifactExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_host_artifact_days", HostArtifactExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_certificate_days", CertificateExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        IocExclusionSettings.Set(database, "ioc_expiry_other_days", OtherExpiryDays.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Notice = "IOC expiry settings saved.";
        return RedirectToPage();
    }

    private void Load()
    {
        IocExclusions = database.Query("SELECT id,value,created_utc FROM ioc_exclusions ORDER BY value COLLATE NOCASE");
        ExcludeM365 = IocExclusionSettings.Get(database, "exclude_m365_endpoints") == "true";
        M365RefreshedUtc = IocExclusionSettings.Get(database, "m365_endpoints_refreshed_utc");
        M365RefreshError = IocExclusionSettings.Get(database, "m365_endpoints_error");
        ExpiryDays = ExpirySettings.Read(database);
        IpExpiryDays = ExpiryDays.Ip;
        DomainExpiryDays = ExpiryDays.Domain;
        HashExpiryDays = ExpiryDays.Hash;
        UrlExpiryDays = ExpiryDays.Url;
        EmailExpiryDays = ExpiryDays.Email;
        SoftwareIdExpiryDays = ExpiryDays.SoftwareId;
        FileArtifactExpiryDays = ExpiryDays.FileArtifact;
        HostArtifactExpiryDays = ExpiryDays.HostArtifact;
        CertificateExpiryDays = ExpiryDays.Certificate;
        OtherExpiryDays = ExpiryDays.Other;
    }
}
