using Microsoft.AspNetCore.Builder;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class InsightsTests
{
    [Fact]
    public void Empty_database_produces_empty_category_and_activity_data()
    {
        using var fixture = DatabaseFixture.Create();
        var page = new InsightsModel(fixture.Database);

        page.OnGet(30);

        Assert.Equal(0, page.ArticleCount);
        Assert.All(page.Categories, category => Assert.Empty(category.Entities));
        Assert.All(page.Activity, bucket => Assert.Equal(0, bucket.ArticleCount));
        Assert.Empty(page.RisingEntities);
    }

    [Fact]
    public void Counts_unique_articles_per_entity_and_compares_with_previous_window()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        Insert(db, "Current report one", DateTimeOffset.UtcNow.AddDays(-1), """
            {"vendors":[{"name":"Northstar Systems"},{"name":"Northstar Systems"}],"industries":[{"name":"Healthcare"}],"threat_actors":[{"name":"Night Heron"}]}
            """);
        Insert(db, "Current report two", DateTimeOffset.UtcNow.AddDays(-4), """
            {"vendors":[{"name":"Northstar Systems"},{"name":"Acme Security Group"}],"industries":[{"name":"Healthcare, Manufacturing"}],"threat_actors":[]}
            """);
        Insert(db, "Previous report", DateTimeOffset.UtcNow.AddDays(-10), """
            {"vendors":[{"name":"Northstar Systems"}],"industries":[{"name":"Healthcare"}],"threat_actors":[{"name":"Night Heron"}]}
            """);
        Insert(db, "Outside comparison", DateTimeOffset.UtcNow.AddDays(-20), """
            {"vendors":[{"name":"Old Systems"}],"industries":[],"threat_actors":[]}
            """);
        var page = new InsightsModel(db);

        page.OnGet(7);

        Assert.Equal(7, page.Days);
        Assert.Equal(2, page.ArticleCount);
        var vendors = Assert.Single(page.Categories, category => category.Key == "vendors");
        Assert.Equal(2, vendors.EntityCount);
        Assert.Equal(2, Assert.Single(vendors.Entities, entity => entity.Name == "Northstar Systems").ArticleCount);
        Assert.Equal(1, Assert.Single(vendors.Entities, entity => entity.Name == "Acme Security Group").ArticleCount);
        var industries = Assert.Single(page.Categories, category => category.Key == "industries");
        Assert.Equal(2, industries.EntityCount);
        Assert.Equal(2, Assert.Single(industries.Entities, entity => entity.Name == "Healthcare").ArticleCount);
        var northstarRow = Assert.Single(page.CoMentionRows, row => row.Entity.Name == "Northstar Systems");
        Assert.Equal(2, Assert.Single(northstarRow.Cells, cell => cell.Entity.Name == "Healthcare").ArticleCount);
        Assert.Equal(2, page.CoMentionMaximum);
        var risingIndustry = Assert.Single(page.RisingEntities, entity => entity.Name == "Manufacturing");
        Assert.Equal(1, risingIndustry.ArticleCount);
        Assert.Equal(1, risingIndustry.Change);
        Assert.DoesNotContain(vendors.Entities, entity => entity.Name == "Old Systems");
        Assert.Equal(12, page.Activity.Count);
    }

    [Fact]
    public void Uses_valid_time_window_and_ignores_malformed_or_unanalyzed_articles()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        Insert(db, "Inside selected window", DateTimeOffset.UtcNow.AddDays(-20), """
            {"vendors":[{"name":"Window Vendor"}],"industries":[{"name":"Public Sector"}],"threat_actors":[]}
            """);
        Insert(db, "Previous-window co-mention", DateTimeOffset.UtcNow.AddDays(-40), """
            {"vendors":[{"name":"Window Vendor"}],"industries":[{"name":"Public Sector"}],"threat_actors":[]}
            """);
        Insert(db, "Outside selected window", DateTimeOffset.UtcNow.AddDays(-100), """
            {"vendors":[{"name":"Old Vendor"}],"industries":[],"threat_actors":[]}
            """);
        Insert(db, "Broken analysis", DateTimeOffset.UtcNow.AddDays(-1), "not-json");
        db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc,ai_status,analysis_json) VALUES('Fixture','Pending analysis','https://example.test/pending',?,'pending',?)",
            DateTimeOffset.UtcNow.ToString("O"), """{"vendors":[{"name":"Pending Vendor"}],"industries":[],"threat_actors":[]}""");
        var page = new InsightsModel(db);

        page.OnGet(30);

        Assert.Equal(30, page.Days);
        Assert.Equal(1, page.ArticleCount);
        var vendors = Assert.Single(page.Categories, category => category.Key == "vendors");
        Assert.Equal("Window Vendor", Assert.Single(vendors.Entities).Name);
        Assert.DoesNotContain("Old Vendor", vendors.Entities.Select(entity => entity.Name));
        Assert.DoesNotContain("Pending Vendor", vendors.Entities.Select(entity => entity.Name));
        var currentVendorRow = Assert.Single(page.CoMentionRows, row => row.Entity.Name == "Window Vendor");
        Assert.Equal(1, Assert.Single(currentVendorRow.Cells, cell => cell.Entity.Name == "Public Sector").ArticleCount);
    }

    [Fact]
    public void Invalid_time_window_falls_back_to_thirty_days_and_treemap_area_scales_by_article_count()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        Insert(db, "Popular entity", DateTimeOffset.UtcNow.AddDays(-1), """
            {"vendors":[{"name":"Popular"}],"industries":[],"threat_actors":[]}
            """);
        Insert(db, "Popular entity two", DateTimeOffset.UtcNow.AddDays(-2), """
            {"vendors":[{"name":"Popular"}],"industries":[],"threat_actors":[]}
            """);
        Insert(db, "Smaller entity", DateTimeOffset.UtcNow.AddDays(-3), """
            {"vendors":[{"name":"Smaller"}],"industries":[],"threat_actors":[]}
            """);
        var page = new InsightsModel(db);

        page.OnGet(42);

        Assert.Equal(30, page.Days);
        var vendors = Assert.Single(page.Categories, category => category.Key == "vendors");
        var popular = Assert.Single(vendors.Entities, entity => entity.Name == "Popular");
        var smaller = Assert.Single(vendors.Entities, entity => entity.Name == "Smaller");
        var popularTile = Assert.Single(page.TreemapTiles(), tile => tile.Entity.Name == "Popular");
        var smallerTile = Assert.Single(page.TreemapTiles(), tile => tile.Entity.Name == "Smaller");
        Assert.Equal(2, popularTile.Width * popularTile.Height / (smallerTile.Width * smallerTile.Height), precision: 8);
        Assert.Equal(10_000, page.TreemapTiles().Sum(tile => tile.Width * tile.Height), precision: 8);
        Assert.True(page.Activity.First().X < page.Activity.Last().X);
        Assert.True(page.Activity.Min(bucket => bucket.Y) < page.Activity.Max(bucket => bucket.Y));
    }

    [Fact]
    public void Entity_relationships_include_only_entities_mentioned_in_the_same_current_article()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        Insert(db, "Shared report", DateTimeOffset.UtcNow.AddDays(-1), """
            {"vendors":[{"name":"Vendor A"}],"industries":[{"name":"Healthcare"}],"threat_actors":[{"name":"Actor One"}]}
            """);
        Insert(db, "Unrelated report", DateTimeOffset.UtcNow.AddDays(-2), """
            {"vendors":[{"name":"Vendor B"}],"industries":[{"name":"Finance"}],"threat_actors":[]}
            """);
        var page = new InsightsModel(db);

        page.OnGet();

        var vendor = Assert.Single(page.Categories.Single(category => category.Key == "vendors").Entities, entity => entity.Name == "Vendor A");
        Assert.Contains(page.EntityKey(Assert.Single(page.Categories.Single(category => category.Key == "industries").Entities, entity => entity.Name == "Healthcare")), page.RelatedEntityKeys[page.EntityKey(vendor)]);
        Assert.Contains(page.EntityKey(Assert.Single(page.Categories.Single(category => category.Key == "actors").Entities, entity => entity.Name == "Actor One")), page.RelatedEntityKeys[page.EntityKey(vendor)]);
        Assert.DoesNotContain(page.EntityKey(Assert.Single(page.Categories.Single(category => category.Key == "vendors").Entities, entity => entity.Name == "Vendor B")), page.RelatedEntityKeys[page.EntityKey(vendor)]);
    }

    private static void Insert(AppDatabase db, string title, DateTimeOffset observed, string analysis)
    {
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,published_utc,ai_status,analysis_json) VALUES('Fixture',?,?, '',?,?, 'analyzed',?)",
            title, $"https://example.test/{Uri.EscapeDataString(title)}", observed.ToString("O"), observed.ToString("O"), analysis);
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string directory;
        public AppDatabase Database { get; }
        private DatabaseFixture(string directory, AppDatabase database) { this.directory = directory; Database = database; }
        public static DatabaseFixture Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroInsightsTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
            var database = new AppDatabase(environment, path);
            database.Initialize();
            return new DatabaseFixture(path, database);
        }
        public void Dispose() { Database.Dispose(); Directory.Delete(directory, true); }
    }
}
