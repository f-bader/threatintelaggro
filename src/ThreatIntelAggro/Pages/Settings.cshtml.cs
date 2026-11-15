using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class SettingsModel(AppDatabase database, AiModelSettingsService aiModelSettings, IConfiguration configuration, IHttpClientFactory httpClientFactory, BriefingService briefings) : PageModel
{
    public IReadOnlyList<Dictionary<string, string?>> BriefingFollows { get; private set; } = [];
    public IReadOnlyList<string> AvailableBriefingVendors { get; private set; } = [];
    public IReadOnlyList<string> AvailableBriefingIndustries { get; private set; } = [];
    public bool BriefingEnabled { get; private set; } = true;
    public string BriefingTimeUtc { get; private set; } = "06:00";
    public string BriefingPrompt { get; private set; } = BriefingService.DefaultPrompt;
    public bool BriefingFeedActive { get; private set; }
    public bool DiagnosticsVisible { get; private set; }
    [TempData] public string? GeneratedBriefingFeedUrl { get; set; }
    [BindProperty] public string FollowKind { get; set; } = "vendor";
    [BindProperty] public string FollowName { get; set; } = "";
    [BindProperty] public bool BriefingEnabledInput { get; set; } = true;
    [BindProperty] public bool DiagnosticsVisibleInput { get; set; }
    [BindProperty] public string BriefingTimeInput { get; set; } = "06:00";
    [BindProperty] public string? BriefingPromptInput { get; set; } = BriefingService.DefaultPrompt;
    public IReadOnlyList<Dictionary<string, string?>> IocExclusions { get; private set; } = [];
    public bool ExcludeM365 { get; private set; }
    public string M365RefreshedUtc { get; private set; } = "";
    public string M365RefreshError { get; private set; } = "";
    public IocExpiryDays ExpiryDays { get; private set; } = ExpirySettings.ReadDefaults();
    public bool ApiKeyActive { get; private set; }
    public string ApiKeyLastRotatedUtc { get; private set; } = "";
    public AiModelSettings CurrentAiSettings { get; private set; } = new();
    public bool ApiKeyConfigured { get; private set; }
    public IReadOnlyList<string> AvailableModels { get; private set; } = [];
    [BindProperty] public string AiModel { get; set; } = "";
    [BindProperty] public string AiEffort { get; set; } = "";
    [BindProperty] public string ResearchModel { get; set; } = "";
    [BindProperty] public string ResearchEffort { get; set; } = "";
    [BindProperty] public string ArticleModel { get; set; } = "";
    [BindProperty] public string ArticleEffort { get; set; } = "";
    [BindProperty] public string DetectionModel { get; set; } = "";
    [BindProperty] public string DetectionEffort { get; set; } = "";
    [BindProperty] public string RepairModel { get; set; } = "";
    [BindProperty] public string RepairEffort { get; set; } = "";
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
    [TempData] public string? GeneratedApiKey { get; set; }

    public void OnGet()
    {
        Load();
        if (!string.IsNullOrWhiteSpace(GeneratedApiKey) || !string.IsNullOrWhiteSpace(GeneratedBriefingFeedUrl)) Response.Headers.CacheControl = "no-store";
    }

    public IActionResult OnPostSaveAiSettings()
    {
        try
        {
            CurrentAiSettings = aiModelSettings.Save(new AiModelSettings(AiModel.Trim(), AiEffort,
                ResearchModel.Trim(), ResearchEffort, ArticleModel.Trim(), ArticleEffort,
                DetectionModel.Trim(), DetectionEffort, RepairModel.Trim(), RepairEffort));
            Notice = "AI model settings saved. They apply to analyses that start from now on.";
            return RedirectToPage();
        }
        catch (ArgumentException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            Notice = null;
            Load(preserveAiInput: true);
            return Page();
        }
    }

    public async Task<IActionResult> OnPostRefreshModelsAsync(CancellationToken cancellationToken)
    {
        var apiKey = configuration["OpenAI:ApiKey"] ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Notice = "Add the OpenAI API key through deployment configuration before loading model IDs.";
            Load();
            return Page();
        }
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.openai.com/v1/models");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);
            using var response = await httpClientFactory.CreateClient("OpenAIModels").SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            using var document = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            AvailableModels = document.RootElement.GetProperty("data").EnumerateArray()
                .Select(item => item.TryGetProperty("id", out var id) ? id.GetString() : null)
                .Where(id => !string.IsNullOrWhiteSpace(id)).Select(id => id!).OrderBy(id => id, StringComparer.Ordinal).ToArray();
            Notice = $"Loaded {AvailableModels.Count} model IDs. Choose one below or enter a deployment ID manually.";
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException)
        {
            Notice = "Could not load model IDs from OpenAI. Check the credential and network, or enter a model/deployment ID manually.";
            Load();
        }
        return Page();
    }

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

    public IActionResult OnPostSaveBriefing()
    {
        var prompt = (BriefingPromptInput ?? "").Trim();
        if (!TimeOnly.TryParse(BriefingTimeInput, out var time) || prompt.Length > 10000 || (prompt.Length > 0 && prompt.Length < 20))
        {
            Notice = "Enter a valid UTC generation time and a prompt of at most 10,000 characters (or leave it blank to restore the default)."; Load(); return Page();
        }
        IocExclusionSettings.Set(database, "briefing_enabled", BriefingEnabledInput ? "true" : "false");
        IocExclusionSettings.Set(database, "briefing_time_utc", time.ToString("HH:mm"));
        if (prompt.Length == 0) database.Execute("DELETE FROM app_settings WHERE key='briefing_prompt'");
        else IocExclusionSettings.Set(database, "briefing_prompt", prompt);
        Notice = prompt.Length == 0 ? "Threat briefing settings saved. The default system prompt has been restored." : "Threat briefing settings saved."; return RedirectToPage();
    }

    public IActionResult OnPostAddBriefingFollow()
    {
        FollowName = (FollowName ?? "").Trim();
        if (FollowKind is not ("vendor" or "industry") || FollowName.Length is < 2 or > 100)
        { Notice = "Choose a vendor or industry and enter a name between 2 and 100 characters."; Load(); return Page(); }
        var kind = FollowKind;
        var existing = briefings.Available(kind);
        database.Execute("INSERT OR IGNORE INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES(?,?,1,?)", kind, FollowName, existing.Contains(FollowName, StringComparer.OrdinalIgnoreCase) ? 0 : 1);
        Notice = "Followed item added."; return RedirectToPage();
    }

    public IActionResult OnPostToggleBriefingFollow(long id)
    {
        database.Execute("UPDATE briefing_follows SET is_enabled=CASE is_enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", id); Notice = "Followed item status updated."; return RedirectToPage();
    }
    public IActionResult OnPostRemoveBriefingFollow(long id)
    {
        database.Execute("DELETE FROM briefing_follows WHERE id=?", id); Notice = "Followed item removed."; return RedirectToPage();
    }
    public IActionResult OnPostRotateBriefingFeed()
    {
        var token = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        IocExclusionSettings.Set(database, "briefing_rss_hash", BriefingService.HashFeedId(token));
        GeneratedBriefingFeedUrl = $"{Request.Scheme}://{Request.Host}/briefings/rss/{token}";
        Response.Headers.CacheControl = "no-store"; Notice = "Briefing RSS access ID generated. Copy the feed URL now; it cannot be displayed again."; return RedirectToPage();
    }

    public IActionResult OnPostToggleM365(bool enabled)
    {
        IocExclusionSettings.Set(database, "exclude_m365_endpoints", enabled ? "true" : "false");
        Notice = enabled ? "Microsoft 365 URL and IP range exclusions enabled." : "Microsoft 365 URL and IP range exclusions disabled.";
        return RedirectToPage();
    }

    public IActionResult OnPostSaveDiagnosticsVisibility()
    {
        IocExclusionSettings.Set(database, "diagnostics_visible", DiagnosticsVisibleInput ? "true" : "false");
        Notice = DiagnosticsVisibleInput ? "Diagnostics tab enabled." : "Diagnostics tab hidden.";
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

    public IActionResult OnPostRotateApiKey()
    {
        var now = DateTimeOffset.UtcNow;
        var currentHash = IocExclusionSettings.Get(database, "api_key_current_hash");
        if (!string.IsNullOrWhiteSpace(currentHash))
        {
            IocExclusionSettings.Set(database, "api_key_previous_hash", currentHash);
            IocExclusionSettings.Set(database, "api_key_previous_expires_utc", now.AddHours(24).ToString("O"));
        }
        else
        {
            IocExclusionSettings.Set(database, "api_key_previous_hash", "");
            IocExclusionSettings.Set(database, "api_key_previous_expires_utc", "");
        }

        var key = ApiKeySecurity.Generate();
        IocExclusionSettings.Set(database, "api_key_current_hash", ApiKeySecurity.Hash(key));
        IocExclusionSettings.Set(database, "api_key_last_rotated_utc", now.ToString("O"));
        GeneratedApiKey = key;
        Notice = "API key rotated. Copy the new value now; it will not be shown again.";
        return RedirectToPage();
    }

    private void Load(bool preserveAiInput = false)
    {
        BriefingFollows = database.Query("SELECT * FROM briefing_follows ORDER BY kind,name COLLATE NOCASE");
        AvailableBriefingVendors = briefings.Available("vendor");
        AvailableBriefingIndustries = briefings.Available("industry");
        BriefingEnabled = IocExclusionSettings.Get(database, "briefing_enabled") != "false";
        var savedTime = IocExclusionSettings.Get(database, "briefing_time_utc");
        BriefingTimeUtc = TimeOnly.TryParse(savedTime, out var configuredTime) ? configuredTime.ToString("HH:mm") : "06:00";
        BriefingPrompt = BriefingService.ResolvePrompt(IocExclusionSettings.Get(database, "briefing_prompt"));
        BriefingEnabledInput = BriefingEnabled; BriefingTimeInput = BriefingTimeUtc; if (!preserveAiInput) BriefingPromptInput = BriefingPrompt;
        BriefingFeedActive = !string.IsNullOrWhiteSpace(IocExclusionSettings.Get(database, "briefing_rss_hash"));
        DiagnosticsVisible = IocExclusionSettings.Get(database, "diagnostics_visible") == "true";
        DiagnosticsVisibleInput = DiagnosticsVisible;
        ApiKeyConfigured = !string.IsNullOrWhiteSpace(configuration["OpenAI:ApiKey"] ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY"));
        CurrentAiSettings = aiModelSettings.Read();
        if (!preserveAiInput)
        {
            AiModel = CurrentAiSettings.Model;
            AiEffort = CurrentAiSettings.Effort;
            ResearchModel = CurrentAiSettings.ResearchModel;
            ResearchEffort = CurrentAiSettings.ResearchEffort;
            ArticleModel = CurrentAiSettings.ArticleModel;
            ArticleEffort = CurrentAiSettings.ArticleEffort;
            DetectionModel = CurrentAiSettings.DetectionModel;
            DetectionEffort = CurrentAiSettings.DetectionEffort;
            RepairModel = CurrentAiSettings.RepairModel;
            RepairEffort = CurrentAiSettings.RepairEffort;
        }
        ApiKeyActive = !string.IsNullOrWhiteSpace(IocExclusionSettings.Get(database, "api_key_current_hash"));
        ApiKeyLastRotatedUtc = IocExclusionSettings.Get(database, "api_key_last_rotated_utc");
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
