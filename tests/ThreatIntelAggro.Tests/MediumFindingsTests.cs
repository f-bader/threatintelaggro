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
    [Fact]
    public async Task FeedRefreshRemovesXmlInvalidCharactersAndImportsEntries()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        db.Execute("INSERT INTO feeds(title,url,created_utc) VALUES(?,?,?)", "Fixture feed", "https://example.test/feed.xml", DateTimeOffset.UtcNow.ToString("O"));
        var feedXml = """
            <?xml version="1.0" encoding="utf-8"?>
            <rss version="2.0"><channel><title>Fixture feed</title>
              <item><title>Entry with control character</title><link>https://example.test/one</link><description><![CDATA[BeforeINVALIDAfter]]></description></item>
              <item><title>Valid entry</title><link>https://example.test/two</link></item>
            </channel></rss>
            """.Replace("INVALID", "\u000b", StringComparison.Ordinal);
        using var fetcher = new SafePublicFetcher(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(feedXml, Encoding.UTF8, "application/rss+xml") }));
        var reader = new FeedReader(fetcher, db, NullLogger<FeedReader>.Instance);

        var added = await reader.RefreshAsync(1);

        Assert.Equal(2, added);
        var articles = db.Query("SELECT title,summary FROM articles ORDER BY id");
        Assert.Equal("Entry with control character", articles[0]["title"]);
        Assert.Equal("BeforeAfter", articles[0]["summary"]);
        Assert.Equal("Valid entry", articles[1]["title"]);
        Assert.Null(db.Query("SELECT last_error FROM feeds WHERE id=1").Single()["last_error"]);
    }

    [Fact]
    public async Task FeedRefreshPrefersPublicationDateOverLaterUpdatedDate()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        db.Execute("INSERT INTO feeds(title,url,created_utc) VALUES(?,?,?)", "Fixture feed", "https://example.test/feed.xml", DateTimeOffset.UtcNow.ToString("O"));
        var feedXml = """
            <feed><title>Fixture feed</title><entry>
              <title>Published article</title><link href="https://example.test/article"/>
              <updated>2026-11-14T18:56:00Z</updated><published>2026-11-12T16:20:00Z</published>
            </entry></feed>
            """;
        using var fetcher = new SafePublicFetcher(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(feedXml, Encoding.UTF8, "application/atom+xml") }));
        var reader = new FeedReader(fetcher, db, NullLogger<FeedReader>.Instance);

        Assert.Equal(1, await reader.RefreshAsync(1));

        var article = db.Query("SELECT published_utc,first_seen_utc FROM articles").Single();
        Assert.Equal("2026-11-12T16:20:00.0000000+00:00", article["published_utc"]);
        Assert.NotEqual(article["published_utc"], article["first_seen_utc"]);
    }

    [Fact]
    public void FeedListingFiltersAndSortsEveryDataColumnWithStableNullHandling()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO feeds(title,url,interval_hours,enabled,ioc_auto_approve,last_checked_utc,last_error,created_utc) VALUES(?,?,?,?,?,?,?,?)", "Alpha Research", "https://alpha.example/feed", 6, 1, 1, "2026-11-12T12:00:00Z", null, now);
        db.Execute("INSERT INTO feeds(title,url,interval_hours,enabled,ioc_auto_approve,last_checked_utc,last_error,created_utc) VALUES(?,?,?,?,?,?,?,?)", "Bravo Security", "https://bravo.example/feed", 3, 1, 0, "2026-11-14T12:00:00Z", "timeout", now);
        db.Execute("INSERT INTO feeds(title,url,interval_hours,enabled,ioc_auto_approve,last_checked_utc,last_error,created_utc) VALUES(?,?,?,?,?,?,?,?)", "Charlie Intel", "https://charlie.example/feed", 12, 0, 0, null, null, now);
        db.Execute("INSERT INTO articles(feed_id,feed_title,title,url,first_seen_utc,ai_status) VALUES(?,?,?,?,?,?)", 1, "Alpha Research", "A1", "https://alpha.example/a1", now, "pending");
        db.Execute("INSERT INTO articles(feed_id,feed_title,title,url,first_seen_utc,ai_status) VALUES(?,?,?,?,?,?)", 1, "Alpha Research", "A2", "https://alpha.example/a2", now, "pending");
        db.Execute("INSERT INTO articles(feed_id,feed_title,title,url,first_seen_utc,ai_status) VALUES(?,?,?,?,?,?)", 3, "Charlie Intel", "C1", "https://charlie.example/c1", now, "pending");

        FeedsModel Listing(string sort = "name", string direction = "asc") => new(db, null!) { Sort = sort, Direction = direction };
        string[] Titles(FeedsModel page) { page.OnGet(); return page.Feeds.Select(x => x["title"]!).ToArray(); }

        Assert.Equal(["Alpha Research", "Bravo Security", "Charlie Intel"], Titles(Listing()));
        Assert.Equal(["Charlie Intel", "Bravo Security", "Alpha Research"], Titles(Listing("name", "desc")));
        Assert.Equal(["Bravo Security", "Alpha Research", "Charlie Intel"], Titles(Listing("cadence")));
        Assert.Equal(["Alpha Research", "Charlie Intel", "Bravo Security"], Titles(Listing("articles", "desc")));
        Assert.Equal(["Bravo Security", "Alpha Research", "Charlie Intel"], Titles(Listing("checked", "desc")));
        Assert.Equal(["Bravo Security", "Alpha Research", "Charlie Intel"], Titles(Listing("status")));

        var filtered = Listing();
        filtered.Status = "unreachable";
        filtered.Cadence = "3";
        filtered.IocApproval = "disabled";
        filtered.Search = "BRAVO.EXAMPLE";
        Assert.Equal(["Bravo Security"], Titles(filtered));
        Assert.Equal(3, filtered.TotalFeedCount);

        var invalid = Listing("title; DROP TABLE feeds", "sideways");
        Assert.Equal(["Alpha Research", "Bravo Security", "Charlie Intel"], Titles(invalid));
        Assert.Equal("name", invalid.Sort);
        Assert.Equal("asc", invalid.Direction);
    }

    [Fact]
    public void FeedActionsRedirectWithCurrentFilterAndSortState()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        db.Execute("INSERT INTO feeds(title,url,created_utc) VALUES(?,?,?)", "Feed", "https://example.test/feed", DateTimeOffset.UtcNow.ToString("O"));
        var page = new FeedsModel(db, null!)
        {
            Search = "example",
            Status = "active",
            Cadence = "6",
            IocApproval = "enabled",
            Sort = "articles",
            Direction = "desc"
        };

        var result = Assert.IsType<RedirectToPageResult>(page.OnPostToggle(1));

        Assert.Equal("/Feeds", result.PageName);
        Assert.Equal("example", result.RouteValues!["search"]);
        Assert.Equal("active", result.RouteValues["status"]);
        Assert.Equal("6", result.RouteValues["cadence"]);
        Assert.Equal("enabled", result.RouteValues["iocApproval"]);
        Assert.Equal("articles", result.RouteValues["sort"]);
        Assert.Equal("desc", result.RouteValues["direction"]);
    }

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
        Assert.IsType<BadRequestObjectResult>(page.OnPostBulkClassify(Enumerable.Repeat(tokens[0], 501).ToArray(), "suspicious"));
        Assert.IsType<BadRequestObjectResult>(page.OnPostBulkClassify([tokens[0], tokens[0]], "suspicious"));
        Assert.Equal(0, db.ScalarInt("SELECT COUNT(*) FROM ioc_role_overrides"));
        Assert.IsType<BadRequestObjectResult>(page.OnPostBulkClassify(tokens, "unknown"));
        Assert.IsType<RedirectToPageResult>(page.OnPostBulkClassify(tokens, "suspicious"));
        Assert.Equal("one.example", Assert.Single(IocIndex.Read(db)).Value);
        Assert.Equal(2, IocIndex.Read(db, includeUnapproved: true).Count);
    }

    [Fact]
    public void BulkApproveAndDismissValidateSelectionAndPreserveApproval()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json) VALUES(?,?,?,?,?,?)", "Fixture", "Fixture", "https://example.org", "", now, """{"iocs":[{"type":"domain","value":"malicious.example","role":"malicious"},{"type":"domain","value":"suspicious.example","role":"suspicious"},{"type":"domain","value":"context.example","role":"unknown"}]}""");
        var page = new IocsModel(db);
        page.OnGet();
        var records = page.Records.ToDictionary(x => x.Value, IocsModel.BulkToken);

        Assert.IsType<BadRequestObjectResult>(page.OnPostBulkReview([records["malicious.example"], records["context.example"]], "approve", null));
        Assert.Equal(0, db.ScalarInt("SELECT COUNT(*) FROM ioc_approvals"));

        Assert.IsType<RedirectToPageResult>(page.OnPostBulkReview([records["malicious.example"], records["suspicious.example"]], "approve", null));
        Assert.Equal(2, db.ScalarInt("SELECT COUNT(*) FROM ioc_approvals"));
        Assert.All(IocIndex.Read(db, includeUnapproved: true), ioc => Assert.True(ioc.Approved));

        Assert.IsType<RedirectToPageResult>(page.OnPostBulkReview([records["malicious.example"], records["context.example"]], "dismiss", null));
        Assert.Equal(2, db.ScalarInt("SELECT COUNT(*) FROM ioc_dismissals"));
        Assert.Equal(2, db.ScalarInt("SELECT COUNT(*) FROM ioc_approvals"));
        Assert.Equal("suspicious.example", Assert.Single(IocIndex.Read(db, includeUnapproved: true)).Value);
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
        {"schema_version":"1.2","language":"en","category":"Existing Research","category_rationale":"fixture","summary":{"headline":"fixture","overview":"fixture","key_findings":[],"evidence":[{"source_id":"src_article","locator":"paragraph 1","excerpt":"Fixture article"}]},"iocs":[],"references":[{"source_id":"src_article","url":"https://example.org/","title":"Fixture","kind":"original","inspection_status":"fetched","relevance":"original"}],"mitre_mappings":[],"industries":[],"threat_actors":[],"vendors":[],"products":[],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],"detection_assessment":{"potential":"uncertain","reason":"fixture","evidence":[]},"coverage":{"limitations":[],"uninspected_source_ids":[],"conflicting_claims":[]}}
        """;
        object Draft(string key) => new { local_key = key, alert_title = "Generated", description = "description", severity = "medium", rationale = "reason", kql = "DeviceEvents | take 1", tactic = "", techniques = Array.Empty<string>(), behaviors = new[] { new { description = "fixture behavior", basis = "source_reported", confidence = "high", evidence = new[] { new { source_id = "src_article", locator = "paragraph 1", excerpt = "Fixture article" } } } }, source_ids = new[] { "src_article" }, playbook = new { title = "test", triage_steps = Array.Empty<string>(), investigation_steps = Array.Empty<string>(), response_options = Array.Empty<string>() }, mitre_mappings = Array.Empty<object>(), telemetry = new { tables = Array.Empty<string>(), required_columns = Array.Empty<string>(), assumptions = Array.Empty<string>(), known_gaps = Array.Empty<string>() } };
        var drafts = new[] { Draft("existing"), Draft(duplicateKey ? "existing" : "new") };
        var detectionJson = JsonSerializer.Serialize(new { schema_version = "1.1", outcome = "drafts_generated", reason = "test", detections = drafts, coverage = Array.Empty<string>() });
        var stages = new Queue<string>(["{\"related_sources\":[]}", schemaArticle, detectionJson]);
        using var http = new HttpClient(new AnalysisHandler(stages));
        using var fetcher = new SafePublicFetcher(new AnalysisHandler(new Queue<string>()));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["OpenAI:ApiKey"] = "fixture" }).Build();
        var modelSettings = new AiModelSettingsService(db, config);
        modelSettings.Save(new AiModelSettings("fixture-model", "high", ResearchModel: "fixture-research", ResearchEffort: "low"));
        var service = new AnalysisService(http, fetcher, db, config, NullLogger<AnalysisService>.Instance, modelSettings);
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
            var requestMetadata = db.Query("SELECT stage_key,requested_model,reasoning_effort,config_revision FROM analysis_responses ORDER BY stage_key");
            Assert.Equal(3, requestMetadata.Count);
            Assert.All(requestMetadata.Where(item => item["stage_key"] != "research"), item => Assert.Equal("fixture-model", item["requested_model"]));
            Assert.Equal("fixture-research", requestMetadata.Single(item => item["stage_key"] == "research")["requested_model"]);
            Assert.Equal("low", requestMetadata.Single(item => item["stage_key"] == "research")["reasoning_effort"]);
            Assert.Equal("high", requestMetadata.Single(item => item["stage_key"] == "article-analysis")["reasoning_effort"]);
            Assert.All(requestMetadata, item => Assert.Equal("1", item["config_revision"]));
            var originalSnapshot = db.Query("SELECT config_json FROM article_ai_config WHERE article_id=1")[0]["config_json"]!;
            Assert.Equal("fixture-model", AiModelSettingsService.FromSnapshot(originalSnapshot).Model);
            modelSettings.Save(new AiModelSettings("new-default", "low"));
            Assert.Equal(originalSnapshot, db.Query("SELECT config_json FROM article_ai_config WHERE article_id=1")[0]["config_json"]);
        }
    }

    [Fact]
    public async Task DeniedArticleFetchUsesCitedSearchExcerptFallback()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO feeds(title,url,created_utc) VALUES(?,?,?)", "Akamai Blog", "https://feeds.feedburner.com/akamai/blog", now);
        db.Execute("INSERT INTO articles(feed_id,feed_title,title,url,summary,first_seen_utc,ai_status) VALUES(1,?,?,?,?,?,'pending')", "Akamai Blog", "AI vulnerability surge", "https://www.akamai.com/blog/ai/2026/nov/ai-vulnerability-surge-exposure-response", "Akamai reported an increase in vulnerability exposure.", now);
        const string excerpt = "Akamai said the security issue affected internet-facing systems.";
        var research = JsonSerializer.Serialize(new { related_sources = Array.Empty<object>(), search_excerpts = Array.Empty<object>() });
        var article = """
        {"schema_version":"1.2","language":"en","category":"Existing Research","category_rationale":"Search excerpt supports the reported claim.","summary":{"headline":"Akamai vulnerability report","overview":"Akamai reported exposure in internet-facing systems.","key_findings":[],"evidence":[{"source_id":"src_article","locator":"web search excerpt","excerpt":"__EXCERPT__"}]},"iocs":[],"references":[{"source_id":"src_article","url":"https://www.akamai.com/blog/ai/2026/nov/ai-vulnerability-surge-exposure-response","title":"AI vulnerability surge","kind":"original","inspection_status":"search_excerpt","relevance":"original"}],"mitre_mappings":[],"industries":[],"threat_actors":[],"vendors":[],"products":[],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],"detection_assessment":{"potential":"uncertain","reason":"Insufficient detail.","evidence":[]},"coverage":{"limitations":["Original page was only available as a web-search excerpt."],"uninspected_source_ids":[],"conflicting_claims":[]},"search_excerpts":[{"title":"Akamai blog","url":"https://www.akamai.com/blog/ai/2026/nov/ai-vulnerability-surge-exposure-response","excerpt":"__EXCERPT__"}]}
        """.Replace("__EXCERPT__", excerpt, StringComparison.Ordinal);
        const string detections = "{\"schema_version\":\"1.1\",\"outcome\":\"no_supported_detection\",\"reason\":\"No behavior detail.\",\"detections\":[],\"coverage\":[]}";
        var citedUrl = "https://www.akamai.com/blog/ai/2026/nov/ai-vulnerability-surge-exposure-response";
        var apiHandler = new FallbackAnalysisHandler([research, "The original Akamai article is available and discusses vulnerability discovery.", article, detections], citedUrl, "Akamai blog");
        using var http = new HttpClient(apiHandler);
        using var fetcher = new SafePublicFetcher(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["OpenAI:ApiKey"] = "fixture" }).Build();
        var settings = new AiModelSettingsService(db, config);
        settings.Save(new AiModelSettings("fixture-model", "high"));
        var service = new AnalysisService(http, fetcher, db, config, NullLogger<AnalysisService>.Instance, settings);

        Assert.True(await service.AnalyzeOneAsync(1));
        Assert.Equal(3, apiHandler.Requests.Count(request => request.TryGetProperty("tool_choice", out var choice) && choice.GetString() == "required" && request.GetProperty("tools")[0].GetProperty("type").GetString() == "web_search" && request.GetProperty("include").EnumerateArray().Any(x => x.GetString() == "web_search_call.action.sources")));
        Assert.False(apiHandler.Requests[1].TryGetProperty("text", out _));
        Assert.Equal("", db.Query("SELECT content_text FROM articles WHERE id=1")[0]["content_text"]);
        using (var ledger = JsonDocument.Parse(db.Query("SELECT source_ledger_json FROM articles WHERE id=1")[0]["source_ledger_json"]!))
            Assert.Equal("search_excerpt", ledger.RootElement.EnumerateArray().Single(x => x.GetProperty("source_id").GetString() == "src_article").GetProperty("inspection_status").GetString());
        Assert.Equal(excerpt, db.Query("SELECT content FROM source_snapshots WHERE article_id=1 AND source_id='src_article'")[0]["content"]);
        Assert.Contains(citedUrl, db.Query("SELECT search_citations_json FROM analysis_responses WHERE article_id=1 AND stage_key='research'")[0]["search_citations_json"]);
        Assert.Contains(citedUrl, db.Query("SELECT search_citations_json FROM analysis_responses WHERE article_id=1 AND stage_key='article-search-citations'")[0]["search_citations_json"]);
        Assert.Contains(citedUrl, db.Query("SELECT search_citations_json FROM analysis_responses WHERE article_id=1 AND stage_key='article-analysis'")[0]["search_citations_json"]);
        Assert.DoesNotContain("search_excerpts", db.Query("SELECT analysis_json FROM articles WHERE id=1")[0]["analysis_json"]);
    }

    [Fact]
    public void ReanalysisClearsStageCacheAndQueuesWithoutDiscardingCurrentResult()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        const string oldAnalysis = "{\"old\":true}";
        const string oldLedger = "old-ledger";
        const string savedConfig = "{\"model\":\"saved-model\",\"effort\":\"high\"}";
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,analysis_json,source_ledger_json,ai_status,ai_error) VALUES(?,?,?,?,?,?,?,'analyzed','old error')", "Fixture", "Fixture", "https://example.org/", "Fixture summary", now, oldAnalysis, oldLedger);
        db.Execute("INSERT INTO article_ai_config(article_id,config_json) VALUES(1,?)", savedConfig);
        db.Execute("INSERT INTO analysis_responses(article_id,stage_key,status,result_text,updated_utc) VALUES(1,'research','completed','cached research',?)", now);
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,status,archived,guid,created_utc,updated_utc) VALUES(1,'reviewed','Reviewed detection','Old query','accepted',0,'guid',?,?)", now, now);
        using var http = new HttpClient(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        using var fetcher = new SafePublicFetcher(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var config = new ConfigurationBuilder().Build();
        var settings = new AiModelSettingsService(db, config);
        var service = new AnalysisService(http, fetcher, db, config, NullLogger<AnalysisService>.Instance, settings);

        Assert.True(service.QueueReanalysis(1));

        var article = db.Query("SELECT ai_status,ai_error,analysis_json,source_ledger_json FROM articles WHERE id=1")[0];
        Assert.Equal("pending", article["ai_status"]);
        Assert.Null(article["ai_error"]);
        Assert.Equal(oldAnalysis, article["analysis_json"]);
        Assert.Equal(oldLedger, article["source_ledger_json"]);
        Assert.Equal(0, db.ScalarInt("SELECT COUNT(*) FROM analysis_responses WHERE article_id=1"));
        Assert.Equal(savedConfig, db.Query("SELECT config_json FROM article_ai_config WHERE article_id=1")[0]["config_json"]);
        Assert.Equal("accepted", db.Query("SELECT status FROM detections WHERE article_id=1 AND local_key='reviewed'")[0]["status"]);
        Assert.False(service.QueueReanalysis(1));
    }

    [Fact]
    public void BulkInboxActionsOnlyChangeCompatibleSelectedArticles()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,is_read,ai_status) VALUES('Fixture','Pending','https://example.org/1','summary',?,0,'pending')", now);
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,is_read,ai_status) VALUES('Fixture','Failed','https://example.org/2','summary',?,1,'failed')", now);
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,is_read,ai_status,analysis_json) VALUES('Fixture','Complete','https://example.org/3','summary',?,0,'analyzed','{}')", now);
        using var http = new HttpClient(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        using var fetcher = new SafePublicFetcher(new StaticResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var config = new ConfigurationBuilder().Build();
        var service = new AnalysisService(http, fetcher, db, config, NullLogger<AnalysisService>.Instance, new AiModelSettingsService(db, config));
        var model = new InboxModel(db, service) { SelectedIds = [1, 2, 3] };

        model.OnPostBulk("read", null, null, null, null, null, null, false, null, null);
        Assert.Equal(new[] { "1", "1", "1" }, db.Query("SELECT is_read FROM articles ORDER BY id").Select(x => x["is_read"]));
        model.OnPostBulk("analyze", "all", null, null, null, null, null, false, null, null);
        Assert.Equal(new[] { "pending", "pending", "analyzed" }, db.Query("SELECT ai_status FROM articles ORDER BY id").Select(x => x["ai_status"]));
        model.OnPostBulk("reanalyze", "all", null, null, null, null, null, false, null, null);
        Assert.Equal(new[] { "pending", "pending", "pending" }, db.Query("SELECT ai_status FROM articles ORDER BY id").Select(x => x["ai_status"]));
        Assert.Equal("Queued 1 analyzed article(s) for reanalysis.", model.Notice);
    }

    [Fact]
    public void AiSettingsPersistDefaultsOverridesAndRevision()
    {
        using var fixture = DatabaseFixture.Create();
        var config = new ConfigurationBuilder().Build();
        var service = new AiModelSettingsService(fixture.Database, config);
        Assert.False(service.Read().IsConfigured);
        var saved = service.Save(new AiModelSettings("provider/model-v2", "medium", ResearchEffort: "low", DetectionModel: "deployment-prod", DetectionEffort: "high"));
        var reloaded = new AiModelSettingsService(fixture.Database, config).Read();
        Assert.Equal(1, saved.Revision);
        Assert.Equal(saved, reloaded);
        Assert.Equal(("provider/model-v2", "low"), reloaded.ForStage("research"));
        Assert.Equal(("deployment-prod", "high"), reloaded.ForStage("detection-generation"));
        Assert.Equal(("provider/model-v2", "medium"), reloaded.ForStage("article-analysis"));
        Assert.Equal(2, service.Save(saved with { Effort = "high" }).Revision);
    }

    [Theory]
    [InlineData("invalid model!", "high")]
    [InlineData("valid-model", "unsupported")]
    public void AiSettingsRejectInvalidModelAndEffort(string model, string effort)
    {
        using var fixture = DatabaseFixture.Create();
        var service = new AiModelSettingsService(fixture.Database, new ConfigurationBuilder().Build());
        Assert.Throws<ArgumentException>(() => service.Save(new AiModelSettings(model, effort)));
    }

    [Fact]
    public void AiSettingsImportLegacyValuesOnceForExistingData()
    {
        using var fixture = DatabaseFixture.Create();
        fixture.Database.Execute("INSERT INTO feeds(title,url,created_utc) VALUES(?,?,?)", "Existing", "https://example.org/feed", DateTimeOffset.UtcNow.ToString("O"));
        IocExclusionSettings.Set(fixture.Database, "ai_settings_legacy_pending", "true");
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OpenAI:Model"] = "legacy-model", ["OpenAI:ReasoningEffort"] = "medium",
            ["OpenAI:ResearchEffort"] = "low", ["OpenAI:AnalysisEffort"] = "high", ["OpenAI:RepairEffort"] = "low"
        }).Build();
        var service = new AiModelSettingsService(fixture.Database, config);
        var imported = service.Read();
        Assert.Equal("legacy-model", imported.Model);
        Assert.Equal("medium", imported.Effort);
        Assert.Equal("high", imported.DetectionEffort);
        IocExclusionSettings.Set(fixture.Database, "ai_settings_legacy_pending", "true");
        Assert.Equal(imported, service.Read());
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

    private sealed class FallbackAnalysisHandler(string[] stages, string citedUrl, string citedTitle) : HttpMessageHandler
    {
        private int _index;
        public List<JsonElement> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var body = JsonDocument.Parse(request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            Requests.Add(body.RootElement.Clone());
            var index = _index++;
            object message = new { type = "message", content = new object[] { new { type = "output_text", text = stages[index] } } };
            object[] output;
            if (index == 0)
                output = [new { type = "web_search_call", status = "completed", action = new { type = "search", sources = new[] { new { type = "url", url = citedUrl, title = citedTitle } } } }, message];
            else if (index == 1)
                output = [new { type = "message", content = new object[] { new { type = "output_text", text = stages[index], annotations = new object[] { new { type = "url_citation", url = citedUrl, title = citedTitle } } } } }];
            else if (index == 2)
                output = [new { type = "web_search_call", status = "completed", action = new { type = "open_page", url = citedUrl } }, message];
            else
                output = [message];
            var response = JsonSerializer.Serialize(new { id = $"resp_fixture_{index}", status = "completed", output });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class StaticResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(response(request));
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
