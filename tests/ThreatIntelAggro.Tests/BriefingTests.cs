using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using ThreatIntelAggro;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class BriefingTests
{
    [Theory]
    [InlineData("Microsoft", "MICROSOFT", true)]
    [InlineData("Palo Alto Networks", "Palo-Alto Networks", true)]
    [InlineData("Fortinet", "Fortinet Inc", true)]
    [InlineData("Apple", "Maple", false)]
    public void Fuzzy_matching_is_normalized_and_conservative(string followed, string candidate, bool expected) => Assert.Equal(expected, BriefingMatcher.Matches(followed, candidate));

    [Fact]
    public void Blank_or_missing_prompt_resolves_to_the_default() => Assert.Equal(BriefingService.DefaultPrompt, BriefingService.ResolvePrompt("  "));

    [Fact]
    public async Task Generates_archived_briefing_for_matching_analyzed_articles_and_skips_empty_or_duplicate_windows()
    {
        using var fixture = DatabaseFixture.Create(); var db = fixture.Database; var writer = new FakeWriter(); var service = new BriefingService(db, writer);
        var end = DateTimeOffset.UtcNow; var start = end.AddDays(-1);
        IocExclusionSettings.Set(db, "briefing_prompt", "Daily prompt");
        db.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('vendor','Microsoft',1,0)");
        InsertPendingArticle(db, end.AddHours(-4));
        InsertArticle(db, "Microsoft security advisory", end.AddHours(-1), "Azure SQL data theft investigated.", "Microsofft");
        InsertArticle(db, "Unrelated advisory", end.AddHours(-2), "A generic issue.", "Acme Systems");
        Assert.Equal(1, await service.GenerateAsync(end));
        Assert.Equal(0, await service.GenerateAsync(end));
        Assert.Single(service.Archive);
        Assert.Single(writer.Articles);
        Assert.Contains("fuzzy similarity", writer.Articles[0].VendorMatchReasons[0]);
        Assert.Equal("Daily prompt", writer.Prompt);
        Assert.True(service.HasInProgressAnalysis(end));
        var row = service.Get(long.Parse(service.Archive[0]["id"]!))!;
        Assert.Contains("Microsoft security advisory", row["markdown"]);
        Assert.Contains("1 suspicious domain", row["ioc_summary"]);
        Assert.Equal("1", db.Query("SELECT COUNT(*) AS count FROM briefings")[0]["count"]);
        Assert.Equal(0, await service.GenerateAsync(end.AddDays(-4)));
        Assert.Equal("%PDF-1.4", System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(row["markdown"]!)[..8]));
        Assert.True(System.Text.RegularExpressions.Regex.Matches(System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(string.Join("\n", Enumerable.Repeat("A long archive paragraph for pagination.", 100)))), "/Type /Page\\b").Count >= 2);
        Assert.Equal(1, await service.GenerateAsync(end.AddSeconds(1)));
        var rss = BriefingService.BuildRss("https://aggro.example", db.Query("SELECT id,title,created_utc,executive_summary,detection_summary,ioc_summary,article_snapshot_json FROM briefings"));
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(rss, "<item>").Count);
        Assert.Contains("Detection summary", rss);
        Assert.Contains("https://example.test/Microsoft%20security%20advisory", rss);
        Assert.True(end.AddDays(-1) < end);
    }

    [Fact]
    public async Task Failed_briefing_writer_records_error_and_raw_output_without_creating_a_briefing()
    {
        using var fixture = DatabaseFixture.Create(); var db = fixture.Database;
        var end = DateTimeOffset.UtcNow; var start = end.AddDays(-1);
        db.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('vendor','Microsoft',1,0)");
        InsertArticle(db, "Microsoft security advisory", end.AddHours(-1), "Azure SQL data theft investigated.", "Microsoft");
        var service = new BriefingService(db, new FailingWriter());

        var error = await Assert.ThrowsAsync<BriefingGenerationException>(() => service.GenerateAsync(end));

        Assert.Equal("""{"title":""", error.RawOutput);
        var diagnostic = db.Query("SELECT stage_key,error,raw_output,briefing_window_start_utc,briefing_window_end_utc FROM analysis_diagnostics").Single();
        Assert.Equal("briefing-generation", diagnostic["stage_key"]);
        Assert.Equal("Invalid generated briefing JSON.", diagnostic["error"]);
        Assert.Equal("""{"title":""", diagnostic["raw_output"]);
        Assert.Equal(start.ToUniversalTime().ToString("O"), diagnostic["briefing_window_start_utc"]);
        Assert.Empty(db.Query("SELECT id FROM briefings"));
    }

    [Fact]
    public void Article_diagnostics_keep_raw_response_and_truncate_oversized_output()
    {
        using var fixture = DatabaseFixture.Create(); var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc) VALUES('Fixture','Diagnostic article','https://example.test/diagnostic',?)", now);
        var articleId = long.Parse(db.Query("SELECT id FROM articles WHERE title='Diagnostic article'").Single()["id"]!);

        AnalysisDiagnostics.RecordArticle(db, articleId, "article-analysis", "Invalid IOC role at iocs[0].role.", new string('x', 100_001));

        var row = db.Query("SELECT stage_key,error,raw_output FROM analysis_diagnostics WHERE article_id=?", articleId).Single();
        Assert.Equal("article-analysis", row["stage_key"]);
        Assert.Equal("Invalid IOC role at iocs[0].role.", row["error"]);
        Assert.EndsWith("[truncated]", row["raw_output"]);
        Assert.Equal(100_000 + Environment.NewLine.Length + "[truncated]".Length, row["raw_output"]!.Length);
    }

    private static void InsertArticle(AppDatabase db, string title, DateTimeOffset published, string overview, string vendor)
    {
        var analysis = $$"""
        {"schema_version":"1.1","summary":{"headline":"{{title}}","overview":"{{overview}}","key_findings":[],"evidence":[]},"vendors":[{"name":"{{vendor}}"}],"industries":[{"name":"Healthcare"}],"iocs":[{"type":"domain","value":"bad.example","role":"suspicious"}]}
        """;
        var date = published.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,analysis_json,evidence_verified) VALUES('Fixture',?,?,?,?,?,'analyzed',?,1)", title, $"https://example.test/{Uri.EscapeDataString(title)}", overview, date, date, analysis);
    }

    private static void InsertPendingArticle(AppDatabase db, DateTimeOffset published)
    {
        var date = published.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,published_utc,first_seen_utc,ai_status) VALUES('Fixture','Pending article','https://example.test/pending',?,?,'pending')", date, date);
    }

    private sealed class FakeWriter : IBriefingWriter
    {
        public IReadOnlyList<BriefingArticle> Articles { get; private set; } = [];
        public string Prompt { get; private set; } = "";
        public Task<BriefingDraft> WriteAsync(string prompt, IReadOnlyList<BriefingArticle> articles, IReadOnlyList<Dictionary<string, string?>> detections, CancellationToken ct)
        {
            Prompt = prompt; Articles = articles;
            return Task.FromResult(new BriefingDraft("Daily briefing", "Executive summary", "Detection summary", "1 suspicious domain"));
        }
    }

    private sealed class FailingWriter : IBriefingWriter
    {
        public Task<BriefingDraft> WriteAsync(string prompt, IReadOnlyList<BriefingArticle> articles, IReadOnlyList<Dictionary<string, string?>> detections, CancellationToken ct) =>
            Task.FromException<BriefingDraft>(new BriefingGenerationException("Invalid generated briefing JSON.", """{"title":"""));
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string _directory;
        public AppDatabase Database { get; }
        private DatabaseFixture(string directory, AppDatabase database) { _directory = directory; Database = database; }
        public static DatabaseFixture Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "AggroBriefingTests", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = directory }).Environment; var database = new AppDatabase(environment, directory); database.Initialize(); return new DatabaseFixture(directory, database);
        }
        public void Dispose() { Database.Dispose(); Directory.Delete(_directory, true); }
    }
}
