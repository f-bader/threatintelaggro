using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class GraphTests
{
    [Fact]
    public void Empty_graph_stays_empty_until_a_scope_or_search_is_selected()
    {
        using var fixture = DatabaseFixture.Create();
        var page = new GraphModel(fixture.Database);

        page.OnGet();

        Assert.Empty(page.Graph.Nodes);
        Assert.Empty(page.Graph.Edges);
        Assert.Equal(14, page.SelectedTypes.Count);
    }

    [Fact]
    public void Recent_category_builds_only_verified_article_source_and_entity_evidence()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var recent = InsertArticle(db, "Verified time critical report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge Research", VerifiedAnalysis());
        InsertArticle(db, "Other category report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.NovelResearch, "Other Source", VerifiedAnalysis("Other Vendor"));
        InsertArticle(db, "Unverified report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Unverified Source", VerifiedAnalysis("Unverified Vendor"), verified: false);

        var graph = ThreatGraphBuilder.Build(db, Query("recent", category: null));

        Assert.Equal(1, graph.ArticleCount);
        Assert.Contains(graph.Nodes, node => node.Type == "source" && node.Label == "Signal Ridge Research");
        Assert.Contains(graph.Nodes, node => node.Type == "article" && node.Label == "Verified time critical report");
        Assert.Contains(graph.Nodes, node => node.Type == "vendor" && node.Label == "Northstar Systems");
        Assert.Contains(graph.Nodes, node => node.Type == "product" && node.Label == "EdgeOS");
        Assert.Contains(graph.Nodes, node => node.Type == "vulnerability" && node.Label == "CVE-2026-11842");
        Assert.Contains(graph.Nodes, node => node.Type == "industry" && node.Label == "Telecommunications");
        Assert.Contains(graph.Nodes, node => node.Type == "actor" && node.Label == "Night Heron");
        Assert.DoesNotContain(graph.Nodes, node => node.Label.Contains("Other Vendor", StringComparison.Ordinal));
        Assert.DoesNotContain(graph.Nodes, node => node.Label.Contains("Unverified Vendor", StringComparison.Ordinal));
        Assert.Contains(graph.Edges, edge => edge.Label == "publishes" && edge.Kind == "direct");
        Assert.Contains(graph.Edges, edge => edge.Label == "associated vendor" && edge.Kind == "direct");
        Assert.Contains(graph.Edges, edge => edge.Source.StartsWith("article:", StringComparison.OrdinalIgnoreCase) && edge.Label == "mentions vendor");
        Assert.All(graph.Edges, edge => Assert.Contains(edge.EvidenceTitle, new[] { "Verified time critical report" }));
    }

    [Fact]
    public void One_hop_search_keeps_seed_and_direct_links_without_expanding_through_matching_article()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "Shared vendor report", DateTimeOffset.UtcNow.AddDays(-2), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());
        InsertArticle(db, "Second vendor report", DateTimeOffset.UtcNow.AddDays(-3), ArticleCategories.NovelResearch, "Another Source", VerifiedAnalysis());

        var graph = ThreatGraphBuilder.Build(db, Query("search", search: "Northstar Systems", category: null));

        Assert.Equal(2, graph.ArticleCount);
        Assert.Contains(graph.Nodes, node => node.Type == "vendor" && node.Label == "Northstar Systems");
        Assert.Contains(graph.Nodes, node => node.Type == "article" && node.Label == "Shared vendor report");
        Assert.Contains(graph.Nodes, node => node.Type == "article" && node.Label == "Second vendor report");
        Assert.DoesNotContain(graph.Nodes, node => node.Type == "actor");
        Assert.DoesNotContain(graph.Nodes, node => node.Type == "ioc");
        Assert.All(graph.Edges, edge => Assert.True(edge.Source == "vendor:NORTHSTAR SYSTEMS" || edge.Target == "vendor:NORTHSTAR SYSTEMS"));
    }

    [Fact]
    public void Exact_entity_search_takes_priority_over_article_titles_that_contain_the_same_text()
    {
        using var fixture = DatabaseFixture.Create();
        InsertArticle(fixture.Database, "Night Heron operations expand", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());

        var graph = ThreatGraphBuilder.Build(fixture.Database, Query("search", search: "Night Heron", category: null));

        Assert.Contains(graph.Nodes, node => node.Type == "actor" && node.Label == "Night Heron");
        Assert.Contains(graph.Nodes, node => node.Type == "article" && node.Label == "Night Heron operations expand");
        Assert.DoesNotContain(graph.Nodes, node => node.Type == "vendor");
        Assert.All(graph.Edges, edge => Assert.Contains("actor:NIGHT HERON", new[] { edge.Source, edge.Target }));
    }

    [Fact]
    public void Ioc_status_filter_uses_analyst_override_and_preserves_status_details()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var articleId = InsertArticle(db, "IOC status report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());
        db.Execute("INSERT INTO ioc_role_overrides(article_id,ioc_type,ioc_value,role,updated_utc) VALUES(?,?,?,?,?)", articleId, "domain", "edge-update.example", "malicious", DateTimeOffset.UtcNow.ToString("O"));

        var graph = ThreatGraphBuilder.Build(db, Query("recent", category: null, iocStatus: "malicious"));

        var ioc = Assert.Single(graph.Nodes, node => node.Type == "ioc");
        Assert.Equal("malicious", ioc.IocStatus);
        Assert.Equal("edge-update.example", ioc.Label);
        Assert.DoesNotContain(graph.Nodes, node => node.Type == "article" && node.Label == "No matching report");
    }

    [Fact]
    public void Detections_create_evidence_linked_detection_and_response_recommendation_nodes()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var articleId = InsertArticle(db, "Detection source report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,description,kql,mitre_json,playbook_json,guid,created_utc,updated_utc) VALUES(?,?,?,?,?,?,?,?,?,?)",
            articleId, "fixture", "Suspicious gateway DNS", "Unexpected DNS resolution", "DnsEvents | take 1", """[{"name":"T1190","id":"T1190"}]""",
            """{"title":"Mitigate exposure","response_options":["Restrict exposed management access","Block edge-update.example at DNS"]}""",
            "fixture-guid", DateTimeOffset.UtcNow.ToString("O"), DateTimeOffset.UtcNow.ToString("O"));

        var graph = ThreatGraphBuilder.Build(db, Query("recent", category: null));

        var detection = Assert.Single(graph.Nodes, node => node.Type == "detection");
        var recommendation = Assert.Single(graph.Nodes, node => node.Type == "recommendation" && node.Label == "Restrict exposed management access");
        Assert.Contains(graph.Edges, edge => edge.Source == $"article:{articleId}" && edge.Target == detection.Id && edge.Label == "generated detection");
        Assert.Contains(graph.Edges, edge => edge.Source == detection.Id && edge.Target == recommendation.Id && edge.Label == "recommends");
        Assert.Contains(graph.Nodes, node => node.Type == "technique" && node.Label == "T1190");
    }

    [Fact]
    public void Co_mentions_are_optional_and_type_filter_can_select_no_types()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "Co-mention evidence report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());

        var normal = ThreatGraphBuilder.Build(db, Query("recent", category: null));
        var withCoMentions = ThreatGraphBuilder.Build(db, Query("recent", category: null, coMentions: true));
        var none = ThreatGraphBuilder.Build(db, Query("recent", category: null, types: new HashSet<string>(StringComparer.OrdinalIgnoreCase), typesSpecified: true));

        Assert.DoesNotContain(normal.Edges, edge => edge.Kind == "co-mention");
        Assert.Contains(withCoMentions.Edges, edge => edge.Kind == "co-mention");
        Assert.Empty(none.Nodes);
        Assert.Empty(none.Edges);
    }

    [Fact]
    public void Export_data_returns_filtered_graph_as_json()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "Exported graph report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());
        var page = new GraphModel(db) { ScopeInput = "recent", DaysInput = 90 };

        var result = Assert.IsType<FileContentResult>(page.OnGetExportData());

        Assert.Equal("application/json; charset=utf-8", result.ContentType);
        Assert.Equal("threat-intel-graph.json", result.FileDownloadName);
        var json = System.Text.Encoding.UTF8.GetString(result.FileContents);
        Assert.Contains("\"nodes\"", json);
        Assert.Contains("\"relationships\"", json);
        Assert.Contains("Exported graph report", json);
    }

    [Fact]
    public void Page_model_keeps_requested_filters_and_type_selection_in_the_get_state()
    {
        using var fixture = DatabaseFixture.Create();
        InsertArticle(fixture.Database, "Filtered graph report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());
        var page = new GraphModel(fixture.Database)
        {
            ScopeInput = "recent",
            CategoryInput = ArticleCategories.TimeCritical,
            SourceInput = "Signal Ridge",
            IocStatusInput = "suspicious",
            DaysInput = 30,
            CoMentionsInput = true,
            TypesInput = ["article", "ioc"],
            TypesSpecified = true
        };

        page.OnGet();

        Assert.Equal("recent", page.Scope);
        Assert.Equal("Signal Ridge", page.Source);
        Assert.Equal("suspicious", page.IocStatus);
        Assert.True(page.CoMentions);
        Assert.Equal(new[] { "article", "ioc" }, page.SelectedTypes.Order(StringComparer.OrdinalIgnoreCase));
        Assert.All(page.Graph.Nodes, node => Assert.Contains(node.Type, page.SelectedTypes));
    }

    [Fact]
    public void Recent_and_full_graph_buttons_apply_their_expected_time_windows()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        InsertArticle(db, "Recent report", DateTimeOffset.UtcNow.AddDays(-1), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());
        InsertArticle(db, "Older verified report", DateTimeOffset.UtcNow.AddDays(-120), ArticleCategories.TimeCritical, "Signal Ridge", VerifiedAnalysis());

        var recent = new GraphModel(db) { ScopeOverride = "recent", DaysInput = 0, CategoryInput = "" };
        recent.OnGet();
        var all = new GraphModel(db) { ScopeOverride = "all", DaysInput = 30, CategoryInput = "" };
        all.OnGet();

        Assert.Equal(30, recent.Days);
        Assert.Equal(ArticleCategories.TimeCritical, recent.Category);
        Assert.Equal(1, recent.Graph.ArticleCount);
        Assert.Equal(0, all.Days);
        Assert.Equal(2, all.Graph.ArticleCount);
    }

    private static ThreatGraphQuery Query(
        string scope,
        string? search = null,
        string? category = ArticleCategories.TimeCritical,
        string? source = null,
        string? iocStatus = null,
        int days = 90,
        bool coMentions = false,
        IReadOnlySet<string>? types = null,
        bool typesSpecified = false) =>
        new(scope, search, category, source, iocStatus, days, coMentions,
            types ?? GraphModel.AvailableTypes.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase), typesSpecified);

    private static long InsertArticle(AppDatabase db, string title, DateTimeOffset published, string category, string source, string analysis, bool verified = true)
    {
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,published_utc,first_seen_utc,ai_status,analysis_json,evidence_verified,category) VALUES(?,?,?,?,?,?,'analyzed',?,?,?)",
            source, title, $"https://example.test/{Uri.EscapeDataString(title)}", "Fixture article summary", published.ToString("O"), published.ToString("O"), analysis, verified ? 1 : 0, category);
        return db.ScalarInt("SELECT last_insert_rowid()");
    }

    private static string VerifiedAnalysis(string vendor = "Northstar Systems") => $$"""
        {
          "summary":{"overview":"A detailed report about a suspicious gateway campaign."},
          "vendors":[{"name":"{{vendor}}","rationale":"The article identifies the vendor."}],
          "products":[{"name":"EdgeOS","vendor_name":"{{vendor}}","affected_role":"exploited","evidence":[{"quote":"EdgeOS gateway"}]}],
          "industries":[{"name":"Telecommunications"}],
          "threat_actors":[{"name":"Night Heron"}],
          "malware":[{"name":"RookLoader"}],
          "campaigns":[{"name":"Operation Foghorn"}],
          "vulnerabilities":[{"name":"CVE-2026-11842"}],
          "targeted_countries":[{"name":"Germany"}],
          "mitre_mappings":[{"name":"T1190"}],
          "iocs":[{"type":"domain","value":"edge-update.example","normalized_value":"edge-update.example","role":"suspicious","context":"Suspected command and control domain."}]
        }
        """;

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string directory;
        public AppDatabase Database { get; }
        private DatabaseFixture(string directory, AppDatabase database) { this.directory = directory; Database = database; }
        public static DatabaseFixture Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroGraphTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
            var database = new AppDatabase(environment, path);
            database.Initialize();
            return new DatabaseFixture(path, database);
        }
        public void Dispose() { Database.Dispose(); Directory.Delete(directory, true); }
    }
}
