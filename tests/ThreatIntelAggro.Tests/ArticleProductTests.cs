using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class ArticleProductTests
{
    [Fact]
    public async Task Inbox_uses_saved_default_coverage_view_only_when_the_query_omits_it()
    {
        using var fixture = DatabaseFixture.Create();
        var defaultPage = new InboxModel(fixture.Database, null!);
        await defaultPage.OnGetAsync();
        Assert.Equal("topics", defaultPage.GroupView);

        IocExclusionSettings.Set(fixture.Database, InboxCoverageSettings.DefaultViewKey, "duplicates");
        var configuredPage = new InboxModel(fixture.Database, null!);
        await configuredPage.OnGetAsync();
        Assert.Equal("duplicates", configuredPage.GroupView);

        var explicitPage = new InboxModel(fixture.Database, null!) { GroupView = "articles" };
        await explicitPage.OnGetAsync();
        Assert.Equal("articles", explicitPage.GroupView);
    }

    [Fact]
    public async Task Product_filter_uses_saved_analysis_and_exposes_only_current_product_facets()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        Insert(db, "With product", "Acme Gateway");
        Insert(db, "Without product", "Other Router");
        var page = new InboxModel(db, null!) { Product = "Acme Gateway", State = "all" };

        await page.OnGetAsync();

        Assert.Contains("Acme Gateway", page.Products);
        Assert.Contains("Other Router", page.Products);
        Assert.Single(page.Articles);
        Assert.Equal("With product", page.Articles[0]["title"]);
        Assert.Equal(1, page.ActiveFilterCount);
    }

    [Fact]
    public void Product_filter_persists_after_article_actions()
    {
        using var fixture = DatabaseFixture.Create();
        Insert(fixture.Database, "With product", "Acme Gateway");
        var id = long.Parse(fixture.Database.Query("SELECT id FROM articles WHERE title='With product'").Single()["id"]!);
        var page = new InboxModel(fixture.Database, null!) { Product = "Acme Gateway" };

        var redirect = Assert.IsType<RedirectToPageResult>(page.OnPostRead(id, "all", null, null, null, null, null, true, null, "recent", true));

        Assert.Equal("Acme Gateway", redirect.RouteValues!["product"]);
        Assert.Equal(true, redirect.RouteValues["followedOnly"]);
        Assert.Equal("1", fixture.Database.Query("SELECT is_read FROM articles WHERE id=?", id).Single()["is_read"]);
    }

    [Theory]
    [InlineData("vendor", "Acme")]
    [InlineData("industry", "Healthcare")]
    [InlineData("product", "Acme Gateway")]
    public async Task Followed_filter_matches_enabled_vendor_industry_and_product_follows(string kind, string name)
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var json = $$"""
        {"products":[{"name":"Acme Gateway","vendor_name":"Acme","affected_versions":["3.2.1"],"affected_role":"exploited"}],"industries":[{"name":"Healthcare"}],"vendors":[{"name":"Acme"}],"mitre_mappings":[],"threat_actors":[]}
        """;
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,ai_status,analysis_json) VALUES('Fixture','Followed match','https://example.test/match','',?,'analyzed',?)", DateTimeOffset.UtcNow.ToString("O"), json);
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,ai_status,analysis_json) VALUES('Fixture','No match','https://example.test/other','',?,'analyzed',?)", DateTimeOffset.UtcNow.ToString("O"), "{\"products\":[],\"industries\":[],\"vendors\":[],\"mitre_mappings\":[],\"threat_actors\":[]}");
        db.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES(?,?,1,0)", kind, name);
        var page = new InboxModel(db, null!) { FollowedOnly = true, State = "all" };

        await page.OnGetAsync();

        Assert.Single(page.Articles);
        Assert.Equal("Followed match", page.Articles[0]["title"]);
    }

    [Fact]
    public async Task Followed_filter_excludes_articles_when_all_follows_are_disabled()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        Insert(db, "Acme Gateway", "Acme Gateway");
        db.Execute("INSERT INTO briefing_follows(kind,name,is_enabled,is_custom) VALUES('product','Acme Gateway',0,0)");
        var page = new InboxModel(db, null!) { FollowedOnly = true, State = "all" };

        await page.OnGetAsync();

        Assert.Empty(page.Articles);
    }

    [Fact]
    public void Inbox_summary_display_is_capped_at_500_characters_plus_truncation_marker()
    {
        using var fixture = DatabaseFixture.Create();
        var page = new InboxModel(fixture.Database, null!);

        var displayed = page.DisplaySummary(new string('x', 700));

        Assert.Equal(504, displayed.Length);
        Assert.EndsWith(" […]", displayed);
    }

    [Fact]
    public void New_article_contract_requires_structured_product_impact_fields()
    {
        var schema = (System.Text.Json.Nodes.JsonObject)typeof(AnalysisService).GetMethod("ArticleSchema", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!.Invoke(null, null)!;
        var product = schema["properties"]!["products"]!["items"]!;
        Assert.Contains("vendor_name", product["required"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Contains("affected_versions", product["required"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Contains("affected_role", product["required"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal("1.2", schema["properties"]!["schema_version"]!["enum"]![0]!.GetValue<string>());
    }

    [Fact]
    public void Article_validator_accepts_evidenced_product_scope_and_rejects_invalid_roles_or_sector_ids()
    {
        var schema = (System.Text.Json.Nodes.JsonObject)typeof(AnalysisService).GetMethod("ArticleSchema", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!.Invoke(null, null)!;
        var sources = System.Text.Json.Nodes.JsonNode.Parse("""[{"source_id":"src_article","title":"Fixture","url":"https://example.test/advisory","kind":"original","inspection_status":"fetched","content":"Acme Secure Gateway version 3.2.1 is affected in healthcare."}]""")!.AsArray();
        var evidence = """{"source_id":"src_article","locator":"paragraph 1","excerpt":"Acme Secure Gateway version 3.2.1 is affected in healthcare."}""";
        var articleJson = """
        {"schema_version":"1.2","language":"en","category":"Existing Research","category_rationale":"Fixture.","summary":{"headline":"Fixture","overview":"Fixture","key_findings":[],"evidence":[__EVIDENCE__]},"iocs":[],"references":[{"source_id":"src_article","url":"https://example.test/advisory","title":"Fixture","kind":"original","inspection_status":"fetched","relevance":"original"}],"mitre_mappings":[],"industries":[{"name":"healthcare","sector_id":"healthcare","confidence":"high","basis":"source_reported","rationale":"Fixture.","evidence":[__EVIDENCE__]}],"threat_actors":[],"vendors":[],"products":[{"name":"Acme Secure Gateway","vendor_name":"Acme Systems","affected_versions":["3.2.1"],"affected_role":"exploited","confidence":"high","basis":"source_reported","rationale":"Fixture.","evidence":[__EVIDENCE__]}],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],"detection_assessment":{"potential":"uncertain","reason":"Fixture.","evidence":[]},"coverage":{"limitations":[],"uninspected_source_ids":[],"conflicting_claims":[]}}
        """.Replace("__EVIDENCE__", evidence, StringComparison.Ordinal);
        var article = System.Text.Json.Nodes.JsonNode.Parse(articleJson)!;

        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        sources[0]!["content"] = "Acme Secure Gateway version 3.2.1\r\nis affected in healthcare.";
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        sources[0]!["content"] = "Acme Secure Gateway version 3.2.1 is affected in healthcare.";
        article["products"]![0]!["affected_role"] = "unknown";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["products"]![0]!["affected_role"] = "exploited";
        article["industries"]![0]!["sector_id"] = "unsupported-sector";
        var sectorError = Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        Assert.Contains("sector_id", sectorError.Message);
        article["industries"]![0]!["sector_id"] = "healthcare";
        article["products"]![0]!["evidence"]![0]!["excerpt"] = "Acme gateway exposure was confirmed.";
        var sanitized = System.Text.Json.Nodes.JsonNode.Parse(ArticleEvidenceValidator.ValidateAndSanitize(article.ToJsonString(), sources, schema))!;
        Assert.Empty(sanitized["products"]!.AsArray());
        Assert.Single(sanitized["industries"]!.AsArray());
    }

    private static void Insert(AppDatabase db, string title, string product)
    {
        var now = DateTimeOffset.UtcNow.ToString("O");
        var json = $$"""
        {"products":[{"name":"{{product}}","vendor_name":"Acme","affected_versions":["3.2.1"],"affected_role":"exploited"}],"industries":[],"vendors":[],"mitre_mappings":[],"threat_actors":[]}
        """;
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,ai_status,analysis_json) VALUES('Fixture',?,?, '',?,'analyzed',?)", title, $"https://example.test/{Uri.EscapeDataString(title)}", now, json);
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string directory;
        public AppDatabase Database { get; }
        private DatabaseFixture(string directory, AppDatabase database) { this.directory = directory; Database = database; }
        public static DatabaseFixture Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroArticleProductTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
            var database = new AppDatabase(environment, path);
            database.Initialize();
            return new DatabaseFixture(path, database);
        }
        public void Dispose() { Database.Dispose(); Directory.Delete(directory, true); }
    }
}
