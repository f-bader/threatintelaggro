using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class ArticleGroupingTests
{
    [Fact]
    public void Duplicate_groups_need_canonical_url_or_matching_title_and_content()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "Acme gateway flaw fix", "Researchers confirmed exploitation of the Acme gateway flaw. Administrators should update affected gateways immediately.", "https://example.test/advisory?utm_source=feed", DateTimeOffset.UtcNow.AddHours(-2));
        InsertArticle(db, "Acme gateway flaw fix", "Researchers confirmed exploitation of the Acme gateway flaw. Administrators should update affected gateways immediately.", "https://example.test/advisory?ref=newsletter", DateTimeOffset.UtcNow.AddHours(-1));
        InsertArticle(db, "Separate Acme gateway issue", "A distinct product announcement and maintenance schedule with no vulnerability report.", "https://example.test/other", DateTimeOffset.UtcNow.AddHours(-1));

        var groups = new ArticleGroupingService(db).Build(ReadArticles(db), "duplicates");

        var group = Assert.Single(groups);
        Assert.Equal("duplicate", group.Type);
        Assert.Contains("Same canonical", group.Reason);
        Assert.Equal(2, group.Members.Count);
    }

    [Fact]
    public void Exact_title_duplicates_require_pairwise_close_content_and_a_short_time_window()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var title = "Researchers report Acme gateway authentication bypass details";
        var summary = "Researchers describe an authentication bypass in the Acme gateway. Attackers can exploit the flaw remotely, and administrators should install the vendor security update immediately to protect exposed appliances.";
        InsertArticle(db, title, summary, "https://example.test/a", DateTimeOffset.UtcNow.AddHours(-1));
        InsertArticle(db, title, summary, "https://example.test/b", DateTimeOffset.UtcNow.AddHours(-2));
        InsertArticle(db, title, "A routine maintenance notice announces new dashboard colors, appliance ordering details, and a regional support event for customers.", "https://example.test/c", DateTimeOffset.UtcNow.AddHours(-3));
        InsertArticle(db, title, summary, "https://example.test/old", DateTimeOffset.UtcNow.AddDays(-10));

        var groups = new ArticleGroupingService(db).Build(ReadArticles(db), "duplicates");

        var group = Assert.Single(groups);
        Assert.Equal(2, group.Members.Count);
        Assert.Contains("matching summaries", group.Reason);
    }

    [Fact]
    public void Topic_groups_use_exact_identifiers_campaigns_and_collected_article_references()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var id1 = InsertArticle(db, "CVE-2026-76543 affects Northstar Systems", "Northstar Systems published a response.", "https://example.test/cve-one", DateTimeOffset.UtcNow);
        InsertArticle(db, "CVE-2026-76543 exploitation analysis", "Independent analysis of the same vulnerability.", "https://example.test/cve-two", DateTimeOffset.UtcNow);
        InsertArticle(db, "Northstar Systems releases product news", "Northstar Systems announced a new dashboard.", "https://example.test/vendor", DateTimeOffset.UtcNow);
        var linkedId = InsertArticle(db, "Follow-up coverage", "This article cites the original report.", "https://example.test/follow-up", DateTimeOffset.UtcNow);
        SetVerifiedAnalysis(db, id1, "[]", "[]");
        SetVerifiedAnalysis(db, linkedId, "[]", "[{\"url\":\"https://example.test/cve-one\"}]");

        var groups = new ArticleGroupingService(db).Build(ReadArticles(db), "topics");

        Assert.Contains(groups, group => group.Key == "topic:cve:CVE-2026-76543" && group.Members.Count == 2);
        Assert.Contains(groups, group => group.Type == "topic" && group.Members.Any(member => member.Article["id"] == id1.ToString()) && group.Members.Any(member => member.Article["id"] == linkedId.ToString()));
        Assert.DoesNotContain(groups, group => group.Members.Any(member => member.Article["title"] == "Northstar Systems releases product news"));
    }

    [Fact]
    public void Campaign_groups_require_verified_analysis_and_manual_ignore_rename_and_split_persist()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var analysis = "[{\"name\":\"Operation Blue Lantern\"}]";
        InsertArticle(db, "First campaign report", "Evidence from the first report.", "https://example.test/campaign-1", DateTimeOffset.UtcNow, analysis, verified: true);
        InsertArticle(db, "Second campaign report", "Evidence from the second report.", "https://example.test/campaign-2", DateTimeOffset.UtcNow, analysis, verified: true);
        InsertArticle(db, "Third campaign report", "Evidence from the third report.", "https://example.test/campaign-3", DateTimeOffset.UtcNow, analysis, verified: true);
        InsertArticle(db, "Unverified fourth report", "Unverified campaign mention.", "https://example.test/campaign-4", DateTimeOffset.UtcNow, analysis, verified: false);
        var service = new ArticleGroupingService(db);
        var group = Assert.Single(service.Build(ReadArticles(db), "topics"));

        Assert.Contains("verified article analysis", group.Reason);
        Assert.True(service.Rename(group.Key, "Blue Lantern reporting"));
        Assert.True(service.ExcludeMember(group.Key, long.Parse(group.Members[0].Article["id"]!)));
        Assert.Equal(2, Assert.Single(service.Build(ReadArticles(db), "topics")).Members.Count);
        Assert.True(service.SetIgnored(group.Key, true));
        Assert.Empty(service.Build(ReadArticles(db), "topics", showIgnored: false));
        var ignored = Assert.Single(service.Build(ReadArticles(db), "topics", showIgnored: true));
        Assert.True(ignored.Ignored);
        Assert.Equal("Blue Lantern reporting", ignored.ManualLabel);
        Assert.Equal(2, ignored.Members.Count);
        Assert.True(service.SetIgnored(group.Key, false));
        Assert.Single(service.Build(ReadArticles(db), "topics"));
    }

    [Fact]
    public async Task Luna_name_generation_uses_low_effort_caches_names_and_preserves_manual_names()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "CVE-2026-98765 Acme Gateway security update", "Acme Gateway has a critical security update.", "https://example.test/advisory-a", DateTimeOffset.UtcNow);
        InsertArticle(db, "CVE-2026-98765 Acme Gateway mitigation", "Install the Acme Gateway update to mitigate CVE-2026-98765.", "https://example.test/advisory-b", DateTimeOffset.UtcNow);
        var grouping = new ArticleGroupingService(db);
        var candidates = grouping.Build(ReadArticles(db), "topics");
        var handler = new NamingResponseHandler();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["OpenAI:ApiKey"] = "fixture-key" }).Build();
        var generator = new OpenAiArticleGroupNameGenerator(new SingleClientFactory(handler), configuration, grouping, NullLogger<OpenAiArticleGroupNameGenerator>.Instance);

        var named = await generator.EnsureNamesAsync(candidates, CancellationToken.None);

        Assert.Equal("Acme Gateway authentication issue", Assert.Single(named).GeneratedLabel);
        using var request = JsonDocument.Parse(handler.RequestBody!);
        Assert.Equal("gpt-6-luna", request.RootElement.GetProperty("model").GetString());
        Assert.Equal("low", request.RootElement.GetProperty("reasoning").GetProperty("effort").GetString());
        Assert.False(request.RootElement.GetProperty("store").GetBoolean());
        Assert.Contains("CVE-2026-98765", handler.RequestBody);

        grouping.Rename(named[0].Key, "Analyst chosen title");
        var refreshed = await generator.EnsureNamesAsync(grouping.Build(ReadArticles(db), "topics"), CancellationToken.None);
        Assert.Equal("Analyst chosen title", Assert.Single(refreshed).Label);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public void Missing_effort_configuration_defaults_global_article_and_detection_efforts_to_medium()
    {
        using var fixture = DatabaseFixture.Create();
        IocExclusionSettings.Set(fixture.Database, "ai_settings_legacy_pending", "true");
        var settings = new AiModelSettingsService(fixture.Database, new ConfigurationBuilder().Build()).Read();

        Assert.Equal("medium", settings.Effort);
        Assert.Equal("medium", settings.ArticleEffort);
        Assert.Equal("medium", settings.DetectionEffort);
    }

    [Fact]
    public async Task Inbox_group_view_applies_filters_to_members_and_keeps_unmatched_articles_visible()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "CVE-2026-13579 vendor advisory", "Vendor advisory details.", "https://example.test/first", DateTimeOffset.UtcNow);
        InsertArticle(db, "CVE-2026-13579 independent reporting", "Independent reporting details.", "https://example.test/second", DateTimeOffset.UtcNow.AddMinutes(-5));
        InsertArticle(db, "Unrelated operations note", "Routine operations update.", "https://example.test/third", DateTimeOffset.UtcNow.AddMinutes(-10));
        db.Execute("UPDATE articles SET is_read=1 WHERE title='CVE-2026-13579 independent reporting'");
        Assert.Single(new ArticleGroupingService(db).Build(ReadArticles(db), "topics"));
        var page = new InboxModel(db, null!, new ArticleGroupingService(db)) { State = "unread", GroupView = "topics" };

        await page.OnGetAsync();

        Assert.True(page.ArticleGroups.Count == 1, $"view={page.GroupView}; matched={page.Articles.Count}; ids={string.Join(',', page.Articles.Select(article => article["id"]))}");
        var group = page.ArticleGroups.Single();
        Assert.Equal(2, group.Group.Members.Count);
        Assert.Single(group.MatchingMembers);
        Assert.Equal("CVE-2026-13579 vendor advisory", group.MatchingMembers[0]["title"]);
        Assert.Single(page.Articles);
        Assert.Equal("Unrelated operations note", page.Articles[0]["title"]);
    }

    private static long InsertArticle(AppDatabase db, string title, string summary, string url, DateTimeOffset published, string? campaigns = null, bool verified = false)
    {
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,analysis_json,evidence_verified) VALUES(?,?,?,?,?,?,'analyzed',?,?)",
            "Fixture feed", title, url, summary, published.ToString("O"), published.ToString("O"), Analysis(campaigns ?? "[]", "[]"), verified ? 1 : 0);
        return db.ScalarInt("SELECT last_insert_rowid()");
    }

    private static void SetVerifiedAnalysis(AppDatabase db, long articleId, string campaigns, string references)
    {
        db.Execute("UPDATE articles SET analysis_json=?,evidence_verified=1,ai_status='analyzed' WHERE id=?", Analysis(campaigns, references), articleId);
    }

    private static string Analysis(string campaigns, string references) => $"{{\"campaigns\":{campaigns},\"vulnerabilities\":[],\"references\":{references}}}";
    private static IReadOnlyList<Dictionary<string, string?>> ReadArticles(AppDatabase db) => db.Query("SELECT id,title,url,summary,published_utc,first_seen_utc,is_read,feed_title,ai_status,analysis_json,evidence_verified FROM articles ORDER BY id");

    private sealed class NamingResponseHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string? RequestBody { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var payload = JsonDocument.Parse(RequestBody);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            var key = JsonDocument.Parse(payload.RootElement.GetProperty("input").GetString()!).RootElement[0].GetProperty("key").GetString();
            var text = JsonSerializer.Serialize(new { groups = new[] { new { key, label = "Acme Gateway authentication issue" } } });
            var response = JsonSerializer.Serialize(new { output = new[] { new { content = new[] { new { type = "output_text", text } } } } });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string directory;
        public AppDatabase Database { get; }
        private DatabaseFixture(string directory, AppDatabase database) { this.directory = directory; Database = database; }
        public static DatabaseFixture Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroArticleGroupingTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
            var database = new AppDatabase(environment, path); database.Initialize();
            return new DatabaseFixture(path, database);
        }
        public void Dispose() { Database.Dispose(); Directory.Delete(directory, true); }
    }
}
