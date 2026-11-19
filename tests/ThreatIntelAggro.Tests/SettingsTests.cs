using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class SettingsTests
{
    [Fact]
    public void Diagnostics_tab_is_hidden_by_default_and_setting_persists()
    {
        using var fixture = DatabaseFixture.Create();
        var settings = fixture.CreateSettingsModel();

        settings.OnGet();
        Assert.False(settings.DiagnosticsVisible);
        Assert.Equal("", IocExclusionSettings.Get(fixture.Database, "diagnostics_visible"));

        settings.DiagnosticsVisibleInput = true;
        Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectToPageResult>(settings.OnPostSaveDiagnosticsVisibility());
        settings.OnGet();

        Assert.True(settings.DiagnosticsVisible);
        Assert.Equal("true", IocExclusionSettings.Get(fixture.Database, "diagnostics_visible"));

        settings.DiagnosticsVisibleInput = false;
        settings.OnPostSaveDiagnosticsVisibility();
        settings.OnGet();
        Assert.False(settings.DiagnosticsVisible);
        Assert.Equal("false", IocExclusionSettings.Get(fixture.Database, "diagnostics_visible"));
    }

    [Fact]
    public void Inbox_default_coverage_view_is_topic_groups_and_can_be_configured()
    {
        using var fixture = DatabaseFixture.Create();
        var settings = fixture.CreateSettingsModel();

        settings.OnGet();
        Assert.Equal("topics", settings.DefaultCoverageView);
        Assert.Equal("", IocExclusionSettings.Get(fixture.Database, InboxCoverageSettings.DefaultViewKey));

        settings.DefaultCoverageViewInput = "duplicates";
        Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectToPageResult>(settings.OnPostSaveInboxDefaults());
        settings.OnGet();

        Assert.Equal("duplicates", settings.DefaultCoverageView);
        Assert.Equal("duplicates", IocExclusionSettings.Get(fixture.Database, InboxCoverageSettings.DefaultViewKey));
    }

    [Fact]
    public void Inbox_default_coverage_view_rejects_unknown_values()
    {
        using var fixture = DatabaseFixture.Create();
        var settings = fixture.CreateSettingsModel();
        settings.DefaultCoverageViewInput = "unknown";

        Assert.IsType<Microsoft.AspNetCore.Mvc.RazorPages.PageResult>(settings.OnPostSaveInboxDefaults());
        Assert.Equal("", IocExclusionSettings.Get(fixture.Database, InboxCoverageSettings.DefaultViewKey));
    }

    [Fact]
    public async Task Briefing_follow_controls_add_catalog_and_custom_names_and_preserve_generation()
    {
        using var fixture = DatabaseFixture.Create();
        var end = new DateTimeOffset(2026, 11, 15, 6, 0, 0, TimeSpan.Zero);
        fixture.Database.Execute("INSERT INTO articles(feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,analysis_json,evidence_verified) VALUES(?,?,?,?,?,?,?,?,1)",
            "Test feed", "Acme incident", "https://example.test/acme", "Incident overview", end.AddHours(-3).ToString("O"), end.AddHours(-3).ToString("O"), "analyzed",
            """{"vendors":[{"name":"Acme Corporation"}],"industries":[{"name":"Healthcare","sector_id":"healthcare"}],"products":[{"name":"Acme Gateway","vendor_name":"Acme Corporation"}],"summary":{"overview":"A supported incident overview."},"iocs":[]}""");
        var settings = fixture.CreateSettingsModel();
        var briefingService = new BriefingService(fixture.Database, new EmptyWriter());

        settings.OnGet();
        Assert.Contains("Acme Corporation", settings.AvailableBriefingVendors);
        Assert.Contains("Healthcare", settings.AvailableBriefingIndustries);
        Assert.Contains("Acme Gateway", settings.AvailableBriefingProducts);

        settings.FollowKind = "vendor";
        settings.FollowName = "Acme Corporation";
        Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectToPageResult>(settings.OnPostAddBriefingFollow());
        var catalogFollow = fixture.Database.Query("SELECT * FROM briefing_follows WHERE kind='vendor'").Single();
        Assert.Equal("0", catalogFollow["is_custom"]);

        settings.FollowKind = "industry";
        settings.FollowName = "Healthcare providers";
        Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectToPageResult>(settings.OnPostAddBriefingFollow());
        var customFollow = fixture.Database.Query("SELECT * FROM briefing_follows WHERE kind='industry'").Single();
        Assert.Equal("1", customFollow["is_custom"]);
        settings.FollowKind = "product";
        settings.FollowName = "Acme Gateway";
        Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectToPageResult>(settings.OnPostAddBriefingFollow());
        var productFollow = fixture.Database.Query("SELECT * FROM briefing_follows WHERE kind='product'").Single();
        Assert.Equal("0", productFollow["is_custom"]);
        Assert.Equal(3, briefingService.Followed.Count);

        var generated = await briefingService.GenerateAsync(end);
        Assert.Equal(1, generated);
        var briefing = briefingService.Latest;
        Assert.NotNull(briefing);
        Assert.Contains("Acme Corporation", briefing["article_snapshot_json"]);

        settings.OnPostToggleBriefingFollow(long.Parse(customFollow["id"]!));
        Assert.Equal("0", fixture.Database.Query("SELECT * FROM briefing_follows WHERE id=?", long.Parse(customFollow["id"]!)).Single()["is_enabled"]);
        settings.OnPostRemoveBriefingFollow(long.Parse(customFollow["id"]!));
        Assert.Equal(2, briefingService.Followed.Count);
    }

    [Fact]
    public void Briefing_follow_migration_preserves_existing_rows_and_allows_products()
    {
        using var fixture = DatabaseFixture.Create();
        fixture.Database.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('industry','Healthcare',0,1)");
        fixture.Database.Execute("BEGIN IMMEDIATE; CREATE TABLE briefing_follows_legacy (id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL CHECK(kind IN ('vendor','industry')),name TEXT NOT NULL,is_enabled INTEGER NOT NULL DEFAULT 1,is_custom INTEGER NOT NULL DEFAULT 0,UNIQUE(kind,name COLLATE NOCASE)); INSERT INTO briefing_follows_legacy SELECT * FROM briefing_follows; DROP TABLE briefing_follows; ALTER TABLE briefing_follows_legacy RENAME TO briefing_follows; COMMIT;");

        fixture.Database.Initialize();

        var preserved = Assert.Single(fixture.Database.Query("SELECT * FROM briefing_follows"));
        Assert.Equal("industry", preserved["kind"]);
        Assert.Equal("Healthcare", preserved["name"]);
        Assert.Equal("0", preserved["is_enabled"]);
        Assert.Equal("1", preserved["is_custom"]);
        fixture.Database.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('product','Acme Gateway',1,0)");
        Assert.Equal("Acme Gateway", fixture.Database.Query("SELECT name FROM briefing_follows WHERE kind='product'").Single()["name"]);
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string _directory;
        public AppDatabase Database { get; }
        private DatabaseFixture(string directory, AppDatabase database) { _directory = directory; Database = database; }

        public static DatabaseFixture Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "AggroSettingsTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = directory }).Environment;
            var database = new AppDatabase(environment, directory);
            database.Initialize();
            return new DatabaseFixture(directory, database);
        }

        public SettingsModel CreateSettingsModel()
        {
            using var services = new ServiceCollection().AddHttpClient().BuildServiceProvider();
            var configuration = new ConfigurationBuilder().Build();
            var writer = new EmptyWriter();
            return new SettingsModel(Database, new AiModelSettingsService(Database, configuration), configuration,
                services.GetRequiredService<IHttpClientFactory>(), new BriefingService(Database, writer));
        }

        public void Dispose() { Database.Dispose(); Directory.Delete(_directory, true); }
    }

    private sealed class EmptyWriter : IBriefingWriter
    {
        public Task<BriefingDraft> WriteAsync(string prompt, IReadOnlyList<BriefingArticle> articles, IReadOnlyList<Dictionary<string, string?>> detections, CancellationToken ct)
            => Task.FromResult(new BriefingDraft("", "", "", ""));
    }
}
