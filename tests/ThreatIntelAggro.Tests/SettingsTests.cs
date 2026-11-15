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
