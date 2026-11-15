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
    public async Task Briefing_follow_controls_add_catalog_and_custom_names_and_preserve_generation()
    {
        using var fixture = DatabaseFixture.Create();
        var end = new DateTimeOffset(2026, 11, 15, 6, 0, 0, TimeSpan.Zero);
        fixture.Database.Execute("INSERT INTO articles(feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,analysis_json,evidence_verified) VALUES(?,?,?,?,?,?,?,?,1)",
            "Test feed", "Acme incident", "https://example.test/acme", "Incident overview", end.AddHours(-3).ToString("O"), end.AddHours(-3).ToString("O"), "analyzed",
            """{"vendors":[{"name":"Acme Corporation"}],"industries":[{"name":"Healthcare"}],"summary":{"overview":"A supported incident overview."},"iocs":[]}""");
        var settings = fixture.CreateSettingsModel();
        var briefingService = new BriefingService(fixture.Database, new EmptyWriter());

        settings.OnGet();
        Assert.Contains("Acme Corporation", settings.AvailableBriefingVendors);
        Assert.Contains("Healthcare", settings.AvailableBriefingIndustries);

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
        Assert.Equal(2, briefingService.Followed.Count);

        var generated = await briefingService.GenerateAsync(end);
        Assert.Equal(1, generated);
        var briefing = briefingService.Latest;
        Assert.NotNull(briefing);
        Assert.Contains("Acme Corporation", briefing["article_snapshot_json"]);

        settings.OnPostToggleBriefingFollow(long.Parse(customFollow["id"]!));
        Assert.Equal("0", fixture.Database.Query("SELECT * FROM briefing_follows WHERE id=?", long.Parse(customFollow["id"]!)).Single()["is_enabled"]);
        settings.OnPostRemoveBriefingFollow(long.Parse(customFollow["id"]!));
        Assert.Single(briefingService.Followed);
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
