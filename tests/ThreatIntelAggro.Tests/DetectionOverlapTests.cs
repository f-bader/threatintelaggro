using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;
using ThreatIntelAggro;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class DetectionOverlapTests
{
    [Fact]
    public void MatcherSuggestsJavaShellVariantsButKeepsDistinctHashRulesApart()
    {
        var first = Detection(1, "Java process spawned a shell or command interpreter",
            "Hunts for Java processes that create shell child processes; legitimate automation can cause matches.",
            "A Java process starts a shell or command interpreter as a child process.",
            "DeviceProcessEvents | where InitiatingProcessFileName in~ (\"java\",\"java.exe\") | where FileName in~ (\"sh\",\"bash\",\"cmd.exe\")");
        var javaVariant = Detection(2, "Java Process Spawning a Shell",
            "A Java process directly launching a shell can indicate suspicious post-exploitation activity.",
            "Hunt for a Java process directly spawning a shell.",
            "DeviceProcessEvents | where InitiatingProcessFileName in~ (\"java.exe\",\"javaw.exe\") | where FileName in~ (\"sh\",\"bash\",\"cmd.exe\")");
        var hashA = Detection(3, "Reported rootkit hash observed", "Exact hash match for a reported rootkit sample.", "",
            "DeviceFileEvents | where SHA256 in~ (\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\")");
        var hashB = Detection(4, "Reported backdoor hash observed", "Exact hash match for a reported backdoor sample.", "",
            "DeviceFileEvents | where SHA256 in~ (\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\")");
        var md5 = Detection(5, "Reported rootkit hash observed", "Exact hash match for a reported rootkit sample.", "",
            "DeviceFileEvents | where MD5 =~ \"14ec33ea808e697870d00c5e434c2952\"");

        var candidates = DetectionOverlapMatcher.FindCandidates(first, [javaVariant, hashA, hashB]);

        Assert.Contains(candidates, x => x.DetectionId == 2);
        Assert.DoesNotContain(candidates, x => x.DetectionId is 3 or 4);
        Assert.Empty(DetectionOverlapMatcher.FindCandidates(hashA, [hashB, md5]));
        var groupedVariant = new Dictionary<string, string?>(javaVariant) { ["family_id"] = "existing-family" };
        Assert.Contains(DetectionOverlapMatcher.FindCandidates(first, [groupedVariant]), x => x.DetectionId == 2);
    }

    [Fact]
    public void IterationGroupingPersistsWithoutChangingDraftsAndCanBeUndone()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc) VALUES('feed','source one','https://one.test/',?)", now);
        db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc) VALUES('feed','source two','https://two.test/',?)", now);
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,status,guid,created_utc,updated_utc) VALUES(1,'one','Rule one','DeviceProcessEvents | take 1','accepted','g1',?,?)", now, now);
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,status,guid,created_utc,updated_utc) VALUES(2,'two','Rule two','DeviceProcessEvents | take 2','new','g2',?,?)", now, now);
        var page = NewPage(db);

        page.OnPostGroupAsIterations(1, 2, "active");

        var grouped = db.Query("SELECT article_id,alert_title,kql,status,family_id,iteration_number FROM detections ORDER BY id");
        Assert.NotNull(grouped[0]["family_id"]);
        Assert.Equal(grouped[0]["family_id"], grouped[1]["family_id"]);
        Assert.Equal(new[] { "1", "2" }, grouped.Select(x => x["iteration_number"]));
        Assert.Equal(new[] { "accepted", "new" }, grouped.Select(x => x["status"]));
        Assert.Equal(new[] { "source one", "source two" }, db.Query("SELECT title FROM articles ORDER BY id").Select(x => x["title"]));
        Assert.Equal("DeviceProcessEvents | take 1", grouped[0]["kql"]);
        Assert.Equal("DeviceProcessEvents | take 2", grouped[1]["kql"]);

        page.OnPostUngroup(1, "active");
        Assert.All(db.Query("SELECT family_id,iteration_number FROM detections"), x =>
        {
            Assert.Null(x["family_id"]);
            Assert.Equal("0", x["iteration_number"]);
        });
    }

    [Fact]
    public void ExistingDifferentFamiliesCannotBeMergedSilently()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc) VALUES('feed','one','https://one.test/',?)", now);
        db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc) VALUES('feed','two','https://two.test/',?)", now);
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,guid,created_utc,updated_utc,family_id,iteration_number) VALUES(1,'one','Rule one','q1','g1',?,?,'family-a',1)", now, now);
        db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,guid,created_utc,updated_utc,family_id,iteration_number) VALUES(2,'two','Rule two','q2','g2',?,?,'family-b',1)", now, now);

        NewPage(db).OnPostGroupAsIterations(1, 2, "active");

        Assert.Equal(new[] { "family-a", "family-b" }, db.Query("SELECT family_id FROM detections ORDER BY id").Select(x => x["family_id"]));
    }

    [Fact]
    public void GroupActionAddsAnUngroupedDraftAsNextIteration()
    {
        using var fixture = DatabaseFixture.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        for (var i = 1; i <= 3; i++)
        {
            db.Execute("INSERT INTO articles(feed_title,title,url,first_seen_utc) VALUES('feed',?,?,?)", $"source {i}", $"https://{i}.test/", now);
            db.Execute("INSERT INTO detections(article_id,local_key,alert_title,kql,status,guid,created_utc,updated_utc) VALUES(?,?,?, ?,?, ?,?,?)", i, $"key-{i}", $"Rule {i}", $"DeviceProcessEvents | take {i}", i == 1 ? "accepted" : "new", $"g{i}", now, now);
        }
        var page = NewPage(db);
        page.OnPostGroupAsIterations(1, 2, "active");
        page.OnPostGroupAsIterations(3, 2, "active");

        var rows = db.Query("SELECT article_id,family_id,iteration_number,status FROM detections ORDER BY iteration_number");
        Assert.Equal(new[] { "1", "2", "3" }, rows.Select(x => x["iteration_number"]));
        Assert.Single(rows.Select(x => x["family_id"]).Distinct());
        Assert.Equal(new[] { "1", "2", "3" }, rows.OrderBy(x => int.Parse(x["article_id"]!)).Select(x => x["iteration_number"]));
        Assert.Equal("accepted", rows.Single(x => x["article_id"] == "1")["status"]);
    }

    private static Dictionary<string, string?> Detection(long id, string title, string description, string behavior, string kql) => new()
    {
        ["id"] = id.ToString(), ["alert_title"] = title, ["description"] = description, ["kql"] = kql,
        ["behaviors_json"] = System.Text.Json.JsonSerializer.Serialize(string.IsNullOrEmpty(behavior) ? Array.Empty<object>() : new object[] { new { description = behavior } }),
        ["telemetry_json"] = System.Text.Json.JsonSerializer.Serialize(new { tables = new[] { kql.StartsWith("DeviceFileEvents", StringComparison.Ordinal) ? "DeviceFileEvents" : "DeviceProcessEvents" } }),
        ["family_id"] = null
    };

    private static Pages.DetectionsModel NewPage(AppDatabase database)
    {
        var page = new Pages.DetectionsModel(database);
        var context = new DefaultHttpContext();
        page.PageContext = new PageContext(new ActionContext(context, new RouteData(), new PageActionDescriptor()));
        page.TempData = new TempDataDictionary(context, new TestTempDataProvider());
        return page;
    }

    private sealed class TestTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string _directory;
        private DatabaseFixture(string directory, AppDatabase database) { _directory = directory; Database = database; }
        public AppDatabase Database { get; }
        public static DatabaseFixture Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroDetectionOverlapTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
            var database = new AppDatabase(environment, path);
            database.Initialize();
            return new DatabaseFixture(path, database);
        }
        public void Dispose() { Database.Dispose(); Directory.Delete(_directory, true); }
    }
}
