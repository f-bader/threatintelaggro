using System.Net;
using System.Text;
using System.Text.Json;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

[CollectionDefinition("Database checks", DisableParallelization = true)]
public sealed class DatabaseChecksCollection;

[Collection("Database checks")]
public sealed class MediumFindingsTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("192.0.2.15")]
    public async Task ForwardedHeadersRequireExplicitTrustedPeer(string? trusted)
    {
        var options = new ForwardedHeadersOptions();
        ForwardedProxyPolicy.Configure(options, trusted is null ? [] : [trusted]);
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.15");
        context.Request.Scheme = "http";
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.77";
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        await new ForwardedHeadersMiddleware(_ => Task.CompletedTask, NullLoggerFactory.Instance, Options.Create(options)).Invoke(context);
        Assert.Equal("203.0.113.15", context.Connection.RemoteIpAddress!.ToString());
        Assert.Equal("http", context.Request.Scheme);
        if (trusted is not null)
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse(trusted);
            await new ForwardedHeadersMiddleware(_ => Task.CompletedTask, NullLoggerFactory.Instance, Options.Create(options)).Invoke(context);
            Assert.Equal("198.51.100.77", context.Connection.RemoteIpAddress!.ToString());
            Assert.Equal("https", context.Request.Scheme);
        }
    }

    [Theory]
    [InlineData("application/json", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"structuredContent\":{\"valid\":true}}}")]
    [InlineData("text/event-stream", ": ping\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{\"structuredContent\":{\"valid\":true}}}\n\n")]
    public void ValidatorParsesJsonAndMultilineEventStreams(string type, string body) => Assert.True(KqlResponseParser.Parse(body, type).GetProperty("valid").GetBoolean());

    [Fact]
    public void ValidatorRejectsMismatchedAndContradictoryResponses()
    {
        Assert.Throws<InvalidOperationException>(() => KqlResponseParser.Parse("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"structuredContent\":{\"valid\":true}}}", "application/json"));
        Assert.Throws<InvalidOperationException>(() => KqlResponseParser.Parse("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"structuredContent\":{\"valid\":false,\"state\":\"valid\"}}}", "application/json"));
    }

    [Fact]
    public void FiltersOldApprovalsAndProtectsEveryCsvField()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        var analysis = """{"iocs":[{"type":"domain","value":"good.example","role":"benign_context"},{"type":"domain","value":"unknown.example","role":"unknown"},{"type":"domain","value":"legacy.example"},{"type":"domain","value":"bad.example","role":"malicious","context":"=1+1"}]}""";
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", " +1+1", "https://example.org", "", now, analysis);
        IocIndex.Approve(db, 1, "domain", "good.example");
        IocIndex.Approve(db, 1, "domain", "unknown.example");
        IocIndex.Approve(db, 1, "domain", "bad.example");
        var results = IocIndex.Read(db, includeUnapproved: true);
        Assert.Single(results);
        Assert.Equal("bad.example", results[0].Value);
        Assert.Equal(3, db.ScalarInt("SELECT COUNT(*) FROM ioc_approvals"));
        var page = new IocsModel(db);
        page.OnGet();
        Assert.Equal(4, page.Records.Count);
        Assert.Contains(page.Records, x => x.Value == "good.example" && x.Approved);
        Assert.Contains(page.Records, x => x.Value == "legacy.example" && !x.Approved);
        var csv = Encoding.UTF8.GetString(Assert.IsType<FileContentResult>(page.OnGetCsv()).FileContents);
        Assert.Contains("\"'=1+1\"", csv);
        Assert.Contains("\"' +1+1\"", csv);
        Assert.DoesNotContain("good.example", csv);
        Assert.DoesNotContain("unknown.example", csv);
        Assert.DoesNotContain("legacy.example", csv);
    }

    [Fact]
    public void AnalystCanClassifyLegacyIndicatorWithoutLosingItsOriginalRoleOrApproval()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        var analysis = """{"iocs":[{"type":"domain","value":"legacy.example","role":"payload delivery domain"},{"type":"domain","value":"pending.example","role":"unknown"},{"type":"domain","value":"benign.example","role":"benign_context"}]}""";
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org", "", now, analysis);
        IocIndex.Approve(db, 1, "domain", "legacy.example");
        Assert.Empty(IocIndex.Read(db, includeUnapproved: true));
        Assert.False(IocIndex.SetReviewedRole(db, 1, "domain", "not-present.example", "malicious"));
        Assert.False(IocIndex.SetReviewedRole(db, 1, "domain", "legacy.example", "unknown"));
        Assert.True(IocIndex.SetReviewedRole(db, 1, "domain", "legacy.example", "malicious"));
        var record = Assert.Single(IocIndex.Read(db));
        Assert.Equal("malicious", record.Role);
        Assert.Equal("payload delivery domain", record.OriginalRole);
        Assert.True(record.Approved);
        Assert.True(IocIndex.SetReviewedRole(db, 1, "domain", "pending.example", "suspicious"));
        Assert.Single(IocIndex.Read(db));
        Assert.Equal(2, IocIndex.Read(db, includeUnapproved: true).Count);
        Assert.DoesNotContain(IocIndex.Read(db, includeUnapproved: true), x => x.Value == "benign.example");
        Assert.Equal(analysis, db.Query("SELECT analysis_json FROM articles WHERE id=1")[0]["analysis_json"]);
        IocIndex.ResetReviewedRole(db, 1, "domain", "legacy.example");
        Assert.Empty(IocIndex.Read(db));
        Assert.Equal(1, db.ScalarInt("SELECT COUNT(*) FROM ioc_approvals WHERE article_id=1 AND ioc_value='legacy.example'"));
    }

    [Fact]
    public void BulkReviewIsExplicitAndAtomicAndKeepsApproval()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org", "", now, """{"iocs":[{"type":"domain","value":"one.example","role":"unknown"},{"type":"domain","value":"two.example","role":"unknown"}]}""");
        IocIndex.Approve(db, 1, "domain", "one.example");
        var page = new IocsModel(db);
        page.OnGet();
        Assert.Equal(2, page.ContextCount);
        Assert.Equal(1, page.PendingCount);
        var tokens = page.Records.Select(IocsModel.BulkToken).ToArray();
        Assert.IsType<BadRequestObjectResult>(page.OnPostBulkClassify([tokens[0], tokens[0]], "suspicious"));
        Assert.Equal(0, db.ScalarInt("SELECT COUNT(*) FROM ioc_role_overrides"));
        Assert.IsType<BadRequestObjectResult>(page.OnPostBulkClassify(tokens, "unknown"));
        Assert.IsType<RedirectToPageResult>(page.OnPostBulkClassify(tokens, "suspicious"));
        Assert.Equal("one.example", Assert.Single(IocIndex.Read(db)).Value);
        Assert.Equal(2, IocIndex.Read(db, includeUnapproved: true).Count);
    }

    [Fact]
    public void ReviewCountsIncludeHiddenReasonsAndCacheRefreshesAfterApproval()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org", "", now, """{"iocs":[{"type":"domain","value":"one.example","role":"malicious"},{"type":"domain","value":"two.example","role":"unknown"}]}""");
        db.Execute("INSERT INTO ioc_dismissals(article_id,ioc_type,ioc_value,dismissed_utc) VALUES(1,'domain','two.example',?)", now);
        var page = new IocsModel(db);
        page.OnGet();
        Assert.Equal(2, page.TotalInRange);
        Assert.Equal(1, page.ArchivedCount);
        Assert.Single(page.Records);
        var cache = new IocCountCache(db);
        Assert.Equal(0, cache.GetCount());
        IocIndex.Approve(db, 1, "domain", "one.example");
        Assert.Equal(1, cache.GetCount());
    }

    [Fact]
    public void OlderMismatchedNormalizedValueIsNeverReturned()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org", "", DateTimeOffset.UtcNow.ToString("O"), """{"iocs":[{"type":"domain","value":"real.example","normalized_value":"unrelated.example","role":"malicious"}]}""");
        IocIndex.Approve(db, 1, "domain", "real.example");
        Assert.Null(Assert.Single(IocIndex.Read(db)).NormalizedValue);
    }

    [Fact]
    public void ClassificationFilterUsesEffectiveRoleAcrossPageCsvAndApi()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        var analysis = """{"iocs":[{"type":"domain","value":"legacy.example","role":"payload domain"},{"type":"domain","value":"bad.example","role":"malicious"},{"type":"domain","value":"context.example","role":"unknown"}]}""";
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org", "", now, analysis);
        IocIndex.Approve(db, 1, "domain", "legacy.example");
        IocIndex.Approve(db, 1, "domain", "bad.example");
        Assert.True(IocIndex.SetReviewedRole(db, 1, "domain", "legacy.example", "suspicious"));
        var page = new IocsModel(db) { Classification = "suspicious" };
        page.OnGet();
        Assert.Equal("legacy.example", Assert.Single(page.Records).Value);
        Assert.Contains("classification=suspicious", page.ApiExampleUrl);
        Assert.Contains("malicious", page.Classifications);
        Assert.Contains("context", page.Classifications);
        var csv = Encoding.UTF8.GetString(Assert.IsType<FileContentResult>(page.OnGetCsv()).FileContents);
        Assert.Contains("legacy.example", csv);
        Assert.DoesNotContain("bad.example", csv);
        Assert.Equal("legacy.example", Assert.Single(IocIndex.Read(db, classification: "suspicious")).Value);
        Assert.Empty(IocIndex.Read(db, includeUnapproved: true, classification: "context"));
        var contextPage = new IocsModel(db) { Classification = "context" };
        contextPage.OnGet();
        Assert.Equal("context.example", Assert.Single(contextPage.Records).Value);
        var contextCsv = Encoding.UTF8.GetString(Assert.IsType<FileContentResult>(contextPage.OnGetCsv()).FileContents);
        Assert.DoesNotContain("context.example", contextCsv);
        var redirect = Assert.IsType<RedirectToPageResult>(page.OnPostResetClassification(1, "domain", "legacy.example"));
        Assert.Equal("suspicious", redirect.RouteValues!["classification"]);
    }

    [Theory]
    [InlineData("=1+1")]
    [InlineData("  @SUM(1)")]
    [InlineData("\ttext")]
    [InlineData("\ufeff =1+1")]
    public void CsvNeutralizesFormulaAndControlPrefixes(string input)
    {
        var csv = (string)typeof(IocsModel).GetMethod("Csv", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [input])!;
        Assert.StartsWith("\"'", csv);
    }

    [Fact]
    public void MappedNetworkMatchesIpv4WithoutCrashing()
    {
        using var fixture = DatabaseFixture.Create();
        fixture.Database.Execute("INSERT INTO ioc_exclusions(value,created_utc) VALUES(?,?)", "::ffff:192.0.2.0/120", DateTimeOffset.UtcNow.ToString("O"));
        var matcher = IocExclusionMatcher.Load(fixture.Database);
        Assert.True(matcher.Excludes("ipv4", "192.0.2.0", null));
        Assert.True(matcher.Excludes("ipv4", "192.0.2.1", null));
        Assert.False(matcher.Excludes("ipv4", "192.0.3.1", null));
    }

    [Fact]
    public void FailedPublicationTransactionRollsBackAllWrites()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        db.Execute("INSERT INTO app_settings(key,value) VALUES(?,?)", "fixture", "original");
        Assert.Throws<InvalidOperationException>(() => db.Transaction(() =>
        {
            db.Execute("UPDATE app_settings SET value='changed' WHERE key='fixture'");
            db.Execute("INSERT INTO app_settings(key,value) VALUES('fixture','duplicate')");
        }));
        Assert.Equal("original", IocExclusionSettings.Get(db, "fixture"));
    }

    [Fact]
    public void OnlineBackupRestoresCommittedWalDataAndKeysAndRejectsTampering()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var directory = fixture.DirectoryPath;
        var keyDirectory = Path.Combine(directory, "keys");
        Directory.CreateDirectory(keyDirectory);
        File.WriteAllText(Path.Combine(keyDirectory, "key-fixture.xml"), "<key>fixture</key>");
        db.Execute("INSERT INTO app_settings(key,value) VALUES('backup-fixture','before')");
        var env = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = directory }).Environment;
        var prior = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR");
        BackupManager manager;
        try { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", directory); manager = new BackupManager(db, env); }
        finally { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior); }
        var backup = manager.CreateBackup();
        db.Execute("UPDATE app_settings SET value='after' WHERE key='backup-fixture'");
        var restored = Path.Combine(directory, "restored");
        BackupManager.RestoreToNewDirectory(backup, restored);
        Assert.Equal("<key>fixture</key>", File.ReadAllText(Path.Combine(restored, "keys", "key-fixture.xml")));
        AppDatabase restoredDb;
        try { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", restored); restoredDb = new AppDatabase(env); }
        finally { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior); }
        using (restoredDb) Assert.Equal("before", IocExclusionSettings.Get(restoredDb, "backup-fixture"));
        Assert.Throws<InvalidOperationException>(() => BackupManager.RestoreToNewDirectory(backup, restored));
        File.AppendAllText(Path.Combine(backup, "aggro.db"), "tampered");
        Assert.Throws<InvalidOperationException>(() => BackupManager.RestoreToNewDirectory(backup, Path.Combine(directory, "bad-restore")));
        Assert.False(Directory.Exists(Path.Combine(directory, "bad-restore")));
    }

    [Fact]
    public void BackupRetentionKeepsDailyAndWeeklySnapshotsAndIgnoresOtherFolders()
    {
        using var fixture = DatabaseFixture.Create();
        var env = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = fixture.DirectoryPath }).Environment;
        var prior = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR");
        BackupManager manager;
        try { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", fixture.DirectoryPath); manager = new BackupManager(fixture.Database, env); }
        finally { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior); }
        var now = DateTimeOffset.UtcNow;
        Directory.CreateDirectory(manager.BackupDirectory);
        for (var day = 0; day < 60; day++)
        {
            var created = now.AddDays(-day);
            var path = Path.Combine(manager.BackupDirectory, $"aggro-{created:yyyyMMddTHHmmssfffZ}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            File.WriteAllText(Path.Combine(path, "manifest.json"), JsonSerializer.Serialize(new BackupManifest("ThreatIntelAggro", 1, created, [])));
        }
        var unrelated = Path.Combine(manager.BackupDirectory, "aggro-manual");
        Directory.CreateDirectory(unrelated);
        manager.Prune(now);
        Assert.Equal(11, Directory.EnumerateDirectories(manager.BackupDirectory, "aggro-*").Count(path => path != unrelated));
        Assert.True(Directory.Exists(unrelated));
    }

    [Fact]
    public void SqliteQueryReportsRuntimeStepErrors()
    {
        using var fixture = DatabaseFixture.Create();
        Assert.Throws<InvalidOperationException>(() => fixture.Database.Query("SELECT abs(-9223372036854775808)"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnalysisPublicationIsAtomicAndPreservesReviewedDetections(bool duplicateKey)
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        const string oldJson = "{\"old\":true}";
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,content_text,analysis_json,source_ledger_json,ai_status) VALUES(?,?,?,?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org/", "", now, "Fixture article", oldJson, "old-ledger", "pending");
        db.Execute("INSERT INTO source_snapshots(article_id,source_id,content) VALUES(1,'old','original')");
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,status,archived,guid,created_utc,updated_utc) VALUES(1,'existing','Reviewed title','Old query','accepted',0,'old-guid',?,?)", now, now);
        var schemaArticle = """
        {"schema_version":"1.1","language":"en","category":"Existing Research","category_rationale":"fixture","summary":{"headline":"fixture","overview":"fixture","key_findings":[],"evidence":[{"source_id":"src_article","locator":"paragraph 1","excerpt":"Fixture article"}]},"iocs":[],"references":[{"source_id":"src_article","url":"https://example.org/","title":"Fixture","kind":"original","inspection_status":"fetched","relevance":"original"}],"mitre_mappings":[],"industries":[],"threat_actors":[],"vendors":[],"products":[],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],"detection_assessment":{"potential":"uncertain","reason":"fixture","evidence":[]},"coverage":{"limitations":[],"uninspected_source_ids":[],"conflicting_claims":[]}}
        """;
        object Draft(string key) => new { local_key = key, alert_title = "Generated", description = "description", severity = "medium", rationale = "reason", kql = "DeviceEvents | take 1", tactic = "", techniques = Array.Empty<string>(), behaviors = new[] { new { description = "fixture behavior", basis = "source_reported", confidence = "high", evidence = new[] { new { source_id = "src_article", locator = "paragraph 1", excerpt = "Fixture article" } } } }, source_ids = new[] { "src_article" }, playbook = new { title = "test", triage_steps = Array.Empty<string>(), investigation_steps = Array.Empty<string>(), response_options = Array.Empty<string>() }, mitre_mappings = Array.Empty<object>(), telemetry = new { tables = Array.Empty<string>(), required_columns = Array.Empty<string>(), assumptions = Array.Empty<string>(), known_gaps = Array.Empty<string>() } };
        var drafts = new[] { Draft("existing"), Draft(duplicateKey ? "existing" : "new") };
        var detectionJson = JsonSerializer.Serialize(new { schema_version = "1.1", outcome = "drafts_generated", reason = "test", detections = drafts, coverage = Array.Empty<string>() });
        var stages = new Queue<string>(["{\"related_sources\":[]}", schemaArticle, detectionJson]);
        using var http = new HttpClient(new AnalysisHandler(stages));
        using var fetcher = new SafePublicFetcher(new AnalysisHandler(new Queue<string>()));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["OpenAI:ApiKey"] = "fixture" }).Build();
        var service = new AnalysisService(http, fetcher, db, config, NullLogger<AnalysisService>.Instance);
        var result = await service.AnalyzeOneAsync(1);
        var article = db.Query("SELECT analysis_json,source_ledger_json,ai_status FROM articles WHERE id=1")[0];
        var detections = db.Query("SELECT local_key,alert_title,kql,status,guid FROM detections WHERE article_id=1 ORDER BY local_key");
        Assert.Equal("old-guid", detections[0]["guid"]);
        Assert.Equal("accepted", detections[0]["status"]);
        Assert.Equal("Old query", detections[0]["kql"]);
        if (duplicateKey)
        {
            Assert.False(result);
            Assert.Equal("failed", article["ai_status"]);
            Assert.Equal(oldJson, article["analysis_json"]);
            Assert.Equal("old-ledger", article["source_ledger_json"]);
            Assert.Single(detections);
            Assert.Equal("original", db.Query("SELECT content FROM source_snapshots WHERE article_id=1 AND source_id='old'")[0]["content"]);
        }
        else
        {
            Assert.True(result);
            Assert.Equal("analyzed", article["ai_status"]);
            Assert.Equal(schemaArticle, article["analysis_json"]);
            Assert.Equal(2, detections.Count);
            Assert.Equal("Fixture article", db.Query("SELECT content FROM source_snapshots WHERE article_id=1 AND source_id='src_article'")[0]["content"]);
        }
    }

    private sealed class AnalysisHandler(Queue<string> stages) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.RequestUri!.Host == "api.openai.com"
                ? JsonSerializer.Serialize(new { id = "resp_fixture", status = "completed", output = new[] { new { type = "message", content = new[] { new { type = "output_text", text = stages.Dequeue() } } } } })
                : "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"structuredContent\":{\"valid\":true}}}";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class DatabaseFixture(string directory, AppDatabase database) : IDisposable
    {
        public AppDatabase Database => database;
        public string DirectoryPath => directory;
        public static DatabaseFixture Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroMediumTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var prior = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR");
            try
            {
                Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", path);
                var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
                var db = new AppDatabase(environment);
                db.Initialize();
                return new DatabaseFixture(path, db);
            }
            finally { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior); }
        }
        public void Dispose() { database.Dispose(); Directory.Delete(directory, true); }
    }
}
