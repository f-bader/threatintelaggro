using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;
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
        db.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('product','Azure SQL',1,0)");
        InsertPendingArticle(db, end.AddHours(-4));
        InsertArticle(db, "Microsoft security advisory", end.AddHours(-1), "Azure SQL data theft investigated.", "Microsofft");
        InsertArticle(db, "Unrelated advisory", end.AddHours(-2), "A generic issue.", "Acme Systems", "Other Router");
        Assert.Equal(1, await service.GenerateAsync(end));
        Assert.Equal(0, await service.GenerateAsync(end));
        Assert.Single(service.Archive);
        Assert.Single(writer.Articles);
        Assert.Contains("fuzzy similarity", writer.Articles[0].VendorMatchReasons[0]);
        Assert.Equal("Azure SQL", writer.Articles[0].ProductMatches);
        Assert.Contains("exact name", writer.Articles[0].ProductMatchReasons[0]);
        Assert.Equal("Daily prompt", writer.Prompt);
        Assert.True(service.HasInProgressAnalysis(end));
        var row = service.Get(long.Parse(service.Archive[0]["id"]!))!;
        Assert.Contains("Microsoft security advisory", row["markdown"]);
        Assert.Contains("Products: Azure SQL", row["markdown"]);
        using (var snapshot = System.Text.Json.JsonDocument.Parse(row["article_snapshot_json"]!))
        {
            Assert.Equal("Azure SQL", BriefingView.ProductMatches(snapshot.RootElement[0]));
            Assert.Contains("Azure SQL matched article value Azure SQL", BriefingView.MatchReasons(snapshot.RootElement[0]));
        }
        Assert.Contains("1 suspicious domain", row["ioc_summary"]);
        Assert.Contains("bad&#91;.&#93;example", row["markdown"]);
        Assert.DoesNotContain("Match reasons:", row["markdown"]);
        Assert.DoesNotContain("matched article value", row["markdown"]);
        using (var iocSnapshot = System.Text.Json.JsonDocument.Parse(row["iocs_snapshot_json"]!))
        {
            Assert.Equal("bad[.]example", iocSnapshot.RootElement[0].GetProperty("Value").GetString());
            Assert.Equal("suspicious", iocSnapshot.RootElement[0].GetProperty("Role").GetString());
        }
        Assert.Equal("1", db.Query("SELECT COUNT(*) AS count FROM briefings")[0]["count"]);
        Assert.Equal(0, await service.GenerateAsync(end.AddDays(-4)));
        Assert.Equal("%PDF-1.4", System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(row["markdown"]!)[..8]));
        Assert.True(System.Text.RegularExpressions.Regex.Matches(System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(string.Join("\n", Enumerable.Repeat("A long archive paragraph for pagination.", 100)))), "/Type /Page\\b").Count >= 2);
        Assert.Equal(1, await service.GenerateAsync(end.AddSeconds(1)));
        var rss = service.ReadRss("https://aggro.example");
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(rss, "<item>").Count);
        Assert.DoesNotContain("Executive summary", rss);
        Assert.DoesNotContain("bad[.]example", rss);
        Assert.Contains("https://example.test/Microsoft%20security%20advisory", rss);
        Assert.True(end.AddDays(-1) < end);
    }

    [Fact]
    public async Task Rss_uses_current_indicator_approvals_and_limits_the_archive()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var service = new BriefingService(db, new FakeWriter());
        var end = DateTimeOffset.UtcNow;
        IocExclusionSettings.Set(db, "briefing_prompt", "Daily prompt");
        db.Execute("INSERT INTO briefing_follows(kind,name) VALUES('vendor','Microsoft')");
        InsertArticle(db, "Supported article", end.AddHours(-1), "Source overview", "Microsoft");
        var id = db.ScalarInt("SELECT id FROM articles WHERE title='Supported article'");
        await service.GenerateAsync(end);
        for (var index = 1; index <= 30; index++)
            await service.GenerateAsync(end.AddSeconds(index));
        IocIndex.Approve(db, id, "domain", "bad.example");

        var rss = System.Xml.Linq.XDocument.Parse(service.ReadRss("https://aggro.example"));
        var items = rss.Descendants("item").ToArray();
        Assert.Equal(30, items.Length);
        Assert.All(items, item => Assert.Contains("bad[.]example", item.Element("description")!.Value));
        Assert.DoesNotContain(items, item => item.Element("guid")!.Value.EndsWith("/1", StringComparison.Ordinal));
        Assert.True(IocIndex.SetReviewedRole(db, id, "domain", "bad.example", "malicious"));
        Assert.Contains("bad[.]example | malicious", service.ReadRss("https://aggro.example"));
        IocIndex.ResetReviewedRole(db, id, "domain", "bad.example");
        db.Execute("INSERT INTO ioc_dismissals(article_id,ioc_type,ioc_value,dismissed_utc) VALUES(?, 'domain', 'bad.example', ?)", id, end.ToString("O"));
        Assert.DoesNotContain("bad[.]example", service.ReadRss("https://aggro.example"));
    }

    [Fact]
    public void Markdown_escapes_untrusted_markup_and_preserves_safe_article_links()
    {
        const string untrusted = "<b>fake</b> ![remote](https://example.test/image) | [link](https://example.test/)";
        var article = new BriefingArticle(1, untrusted, "https://example.test/a(b)?x=1&y=2", "today", "", "", "", "", "", "", [], [], []);
        var draft = new BriefingDraft(untrusted, untrusted, "", untrusted);
        var markdown = BriefingExport.Markdown(draft, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            [article, article with { Url = "file:///tmp/example" }], [new(untrusted, untrusted, "low", "")], [new("domain", untrusted, "unknown")]);

        Assert.DoesNotContain("<b>", markdown);
        Assert.DoesNotContain("![remote]", markdown);
        Assert.DoesNotContain("file://", markdown);
        Assert.Contains("](https://example.test/a%28b%29?x=1&amp;y=2)", markdown);
        Assert.Contains("/Subtype /Link", System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(markdown)));
    }

    [Fact]
    public void Legacy_briefing_snapshots_without_product_fields_remain_readable()
    {
        using var article = System.Text.Json.JsonDocument.Parse("""{"VendorMatches":"Microsoft","IndustryMatches":"Healthcare","VendorMatchReasons":[],"IndustryMatchReasons":[]}""");
        Assert.Equal("", BriefingView.ProductMatches(article.RootElement));
        Assert.Equal("", BriefingView.MatchReasons(article.RootElement));
    }

    [Theory]
    [InlineData("url", "https://evil.example/path", "hxxps://evil[.]example/path")]
    [InlineData("domain", "evil[.]example", "evil[.]example")]
    [InlineData("email", "analyst@evil.example", "analyst@evil[.]example")]
    [InlineData("ipv4", "192.0.2.10", "192[.]0[.]2[.]10")]
    [InlineData("ipv6", "2001:db8::1", "2001[:]db8[:][:]1")]
    public void Defangs_network_indicators(string type, string value, string expected) => Assert.Equal(expected, BriefingIndicators.Defang(type, value));

    [Fact]
    public void Defangs_indicator_values_in_summary_text_and_deduplicates_ioc_rows()
    {
        using var analysis = System.Text.Json.JsonDocument.Parse("""{"iocs":[{"type":"url","value":"https://evil.example/path","role":"malicious"},{"type":"domain","value":"evil.example","role":"malicious"}]}""");
        var text = BriefingIndicators.DefangText("Observed https://evil.example/path hosted on evil.example.", [analysis.RootElement]);
        Assert.Equal("Observed hxxps://evil[.]example/path hosted on evil[.]example.", text);

        var iocs = BriefingIndicators.Distinct([
            new BriefingIoc("domain", "evil[.]example", "malicious"),
            new BriefingIoc("DOMAIN", "evil[.]example", "MALICIOUS")]);
        Assert.Single(iocs);
    }

    [Fact]
    public void Pdf_renders_ioc_rows_as_bounded_table_cells_and_wraps_long_values()
    {
        var hash = new string('a', 64);
        var markdown = $"## IOC summary\n\n| Type | Value | Role |\n| --- | --- | --- |\n| sha256 | {hash} | malicious |";
        var pdf = System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(markdown));

        Assert.Contains("0.91 0.96 0.97 rg", pdf);
        Assert.Contains("0.68 0.76 0.80 RG", pdf);
        Assert.Contains($"({hash[..55]}) Tj ET", pdf);
        Assert.Contains($"({hash[55..]}) Tj ET", pdf);
        Assert.DoesNotContain("sha256   |", pdf);
    }

    [Fact]
    public void Pdf_article_link_bounds_end_at_the_visible_title()
    {
        var pdf = System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf("## Applicable articles\n\n- [Acme](https://example.test/article)"));
        Assert.Matches("/Rect \\[48 \\d+ 73\\.56 \\d+\\]", pdf);
        Assert.Contains("0.08 0.48 0.56 RG 48 ", pdf);
        Assert.Contains("73.56", pdf);
    }

    [Fact]
    public async Task New_briefings_render_detection_details_ioc_overview_and_clickable_article_titles()
    {
        using var fixture = DatabaseFixture.Create(); var db = fixture.Database; var service = new BriefingService(db, new FakeWriter());
        var end = DateTimeOffset.UtcNow;
        db.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('vendor','Microsoft',1,0)");
        InsertArticle(db, "Microsoft security advisory", end.AddHours(-1), "Source overview", "Microsoft");
        var articleId = long.Parse(db.Query("SELECT id FROM articles WHERE title='Microsoft security advisory'").Single()["id"]!);
        var now = end.ToString("O");
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,description,severity,kql,guid,created_utc,updated_utc) VALUES(?,?,?,?,?,'DeviceEvents | take 1','fixture-guid',?,?)", articleId, "test", "Suspicious login burst", "Repeated failed sign-ins followed by a successful login.", "high", now, now);

        await service.GenerateAsync(end);

        var briefing = service.Latest!;
        var markdown = briefing["markdown"]!;
        Assert.Contains("### Suspicious login burst", markdown);
        Assert.Contains("Repeated failed sign-ins followed by a successful login.", System.Net.WebUtility.HtmlDecode(markdown));
        Assert.Contains("| Type | Value | Role |", markdown);
        Assert.Contains("| domain | bad&#91;.&#93;example | suspicious |", markdown);
        Assert.DoesNotContain("Detection summary\n\nDetection summary", markdown);
        Assert.DoesNotContain("Match reasons:", markdown);
        var previousCulture = System.Globalization.CultureInfo.CurrentCulture;
        string pdf;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("fr-FR");
            pdf = System.Text.Encoding.ASCII.GetString(BriefingExport.Pdf(markdown));
        }
        finally { System.Globalization.CultureInfo.CurrentCulture = previousCulture; }
        Assert.Contains("/Subtype /Link", pdf);
        Assert.Contains("/URI (https://example.test/Microsoft%20security%20advisory)", pdf);
        Assert.DoesNotMatch("/Rect \\[\\d+ \\d+ \\d+,[\\d]+ \\d+\\]", pdf);
        Assert.Contains("0.91 0.96 0.97 rg", pdf);
        Assert.Contains("(Value)", pdf);
        Assert.Contains("(bad[.]example)", pdf);
        Assert.DoesNotContain("Type   |   Value   |   Role", pdf);
        Assert.DoesNotContain("<https://example.test/Microsoft", pdf);
    }

    [Fact]
    public void Legacy_briefing_snapshots_can_recover_indicators_and_detections_from_existing_articles()
    {
        using var fixture = DatabaseFixture.Create(); var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        InsertArticle(db, "Microsoft advisory", DateTimeOffset.UtcNow, "Overview", "Microsoft");
        var articleId = long.Parse(db.Query("SELECT id FROM articles WHERE title='Microsoft advisory'").Single()["id"]!);
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,description,kql,guid,created_utc,updated_utc) VALUES(?,?,?,?,'DeviceEvents | take 1','legacy-guid',?,?)", articleId, "legacy", "Legacy detection", "Legacy description", now, now);
        db.Execute("INSERT INTO briefings(window_start_utc,window_end_utc,created_utc,title,executive_summary,detection_summary,ioc_summary,article_ids_json,article_snapshot_json,markdown) VALUES(?,?,?,?,?,?,?,?,?,?)", now, now, now, "Legacy", "Summary", "Old detection prose", "Old IOC summary", System.Text.Json.JsonSerializer.Serialize(new[] { articleId.ToString() }), "[]", "legacy markdown");
        var service = new BriefingService(db, new FakeWriter());
        var oldBriefing = service.Latest!;

        Assert.Equal("Legacy detection", Assert.Single(service.GetDetections(oldBriefing)).Title);
        Assert.Equal("bad[.]example", Assert.Single(service.GetIocs(oldBriefing)).Value);
        var markdown = service.ReadMarkdown(oldBriefing);
        Assert.Contains("### Legacy detection", markdown);
        Assert.DoesNotContain("legacy markdown", markdown);
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

    private static void InsertArticle(AppDatabase db, string title, DateTimeOffset published, string overview, string vendor, string product = "Azure SQL")
    {
        var analysis = $$"""
        {"schema_version":"1.2","summary":{"headline":"{{title}}","overview":"{{overview}}","key_findings":[],"evidence":[]},"vendors":[{"name":"{{vendor}}"}],"industries":[{"name":"Healthcare","sector_id":"healthcare"}],"products":[{"name":"{{product}}","vendor_name":"Microsoft","affected_versions":[],"affected_role":"mentioned_affected"}],"iocs":[{"type":"domain","value":"bad.example","role":"suspicious"}]}
        """;
        var date = published.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,analysis_json,evidence_verified) VALUES('Fixture',?,?,?,?,?,'analyzed',?,1)", title, $"https://example.test/{Uri.EscapeDataString(title)}", overview, date, date, analysis);
    }

    private static void InsertPendingArticle(AppDatabase db, DateTimeOffset published)
    {
        var date = published.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,published_utc,first_seen_utc,ai_status) VALUES('Fixture','Pending article','https://example.test/pending',?,?,'pending')", date, date);
    }

    [Fact]
    public async Task Manual_briefing_job_reports_progress_deduplicates_and_archives()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        db.Execute("INSERT INTO briefing_follows(kind,name) VALUES('vendor','Microsoft')");
        InsertArticle(db, "Fixture report", DateTimeOffset.UtcNow.AddHours(-1), "Observed evidence.", "Microsoft");
        var writer = new BlockingWriter();
        using var provider = new ServiceCollection().AddScoped(_ => new BriefingService(db, writer)).BuildServiceProvider();
        using var jobs = new ManualJobs(provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<ManualJobs>.Instance);
        Assert.Equal("queued", jobs.EnqueueBriefing().State);
        Assert.Equal("queued", jobs.EnqueueBriefing().State);
        await jobs.StartAsync(CancellationToken.None);
        try
        {
            await writer.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("running", jobs.EnqueueBriefing().State);
            writer.Release.SetResult();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (jobs.Status(ManualJobs.BriefingKey)?.State == "running")
                await Task.Delay(10, timeout.Token);
            Assert.Equal("complete", jobs.Status(ManualJobs.BriefingKey)?.State);
            Assert.Single(db.Query("SELECT id FROM briefings"));
        }
        finally { await jobs.StopAsync(CancellationToken.None); }
    }

    private sealed class BlockingWriter : IBriefingWriter
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<BriefingDraft> WriteAsync(string prompt, IReadOnlyList<BriefingArticle> articles,
            IReadOnlyList<Dictionary<string, string?>> detections, CancellationToken ct)
        {
            Started.TrySetResult();
            await Release.Task.WaitAsync(ct);
            return new BriefingDraft("Fixture briefing", "Executive summary", "Detection summary", "IOC summary");
        }
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
