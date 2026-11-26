using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using ThreatIntelAggro;
using ThreatIntelAggro.Pages;
using Xunit;

namespace ThreatIntelAggro.Tests;

[Collection("Database checks")]
public sealed class ScreenshotAnalysisTests
{
    [Fact]
    public async Task ScreenshotUsesVisionThenPublishesAuditableSocialPostAnalysis()
    {
        using var fixture = TestDatabase.Create();
        var db = fixture.Database;
        var now = DateTimeOffset.UtcNow.ToString("O");
        var fixtureImagePath = Environment.GetEnvironmentVariable("AGGRO_SCREENSHOT_FIXTURE");
        var imageBytes = string.IsNullOrWhiteSpace(fixtureImagePath) ? Convert.FromBase64String("iVBORw0KGgo=") : File.ReadAllBytes(fixtureImagePath);
        var imageDataUrl = $"data:image/png;base64,{Convert.ToBase64String(imageBytes)}";
        db.Execute("INSERT INTO articles(feed_title,title,url,summary,first_seen_utc,ai_status,screenshot_data_url) VALUES(?,?,?,?,?,?,?)",
            "Ad hoc · Screenshot", "Social post screenshot", "https://screenshot.invalid/example", "Submitted for one-off analysis.", now, "pending", imageDataUrl);

        const string transcript = "Anurag @Malwarehunterr\nFake Google Meet website observed using ClickFix-style social engineering.\nDomain: g[.]meet.e2qs0[.]com";
        const string extraction = """{"suggested_title":"Fake Google Meet social engineering post","platform":"x","transcript":"Anurag @Malwarehunterr\nFake Google Meet website observed using ClickFix-style social engineering.\nDomain: g[.]meet.e2qs0[.]com","author_name":"Anurag","author_handle":"@Malwarehunterr","author_verified":true,"author_evidence":"Anurag @Malwarehunterr","posted_at":null,"timestamp_evidence":"","post_url":null}""";
        const string research = """{"related_sources":[],"search_excerpts":[]}""";
        const string article = """{"schema_version":"1.2","language":"en","category":"Actionable IOCs","category_rationale":"The post reports a suspicious delivery domain.","summary":{"headline":"Fake Google Meet social engineering","overview":"The post describes a ClickFix-style fake meeting site.","key_findings":[],"evidence":[{"source_id":"src_article","locator":"post text","excerpt":"Fake Google Meet website observed using ClickFix-style social engineering."}]},"iocs":[{"type":"domain","value":"g[.]meet.e2qs0[.]com","normalized_value":"g.meet.e2qs0.com","role":"suspicious","context":"Domain listed as an IOC in the post.","confidence":"high","basis":"source_reported","evidence":[{"source_id":"src_article","locator":"IOC list","excerpt":"Domain: g[.]meet.e2qs0[.]com"}]}],"references":[{"source_id":"src_article","url":"https://screenshot.invalid/example","title":"Fake Google Meet social engineering post","kind":"screenshot","inspection_status":"fetched","relevance":"original post screenshot"}],"mitre_mappings":[],"industries":[],"threat_actors":[],"vendors":[],"products":[],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],"detection_assessment":{"potential":"uncertain","reason":"The post does not provide enough endpoint behavior for a detection draft.","evidence":[]},"coverage":{"limitations":["Post text was transcribed from a screenshot."],"uninspected_source_ids":[],"conflicting_claims":[]}}""";
        const string detections = """{"schema_version":"1.1","outcome":"no_supported_detection","reason":"The screenshot describes behavior but does not provide sufficient telemetry detail.","detections":[],"coverage":[]}""";
        var handler = new ScreenshotModelHandler([extraction, research, article, detections]);
        using var http = new HttpClient(handler);
        using var fetcher = new SafePublicFetcher(new StaticHandler());
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["OpenAI:ApiKey"] = "fixture" }).Build();
        var settings = new AiModelSettingsService(db, config);
        settings.Save(new AiModelSettings("gpt-6-luna", "high"));
        var service = new AnalysisService(http, fetcher, db, config, NullLogger<AnalysisService>.Instance, settings);

        Assert.True(await service.AnalyzeOneAsync(1));

        var firstRequest = handler.Requests[0];
        Assert.Equal("gpt-6-luna", firstRequest.GetProperty("model").GetString());
        var image = firstRequest.GetProperty("input")[0].GetProperty("content")[1];
        Assert.Equal("input_image", image.GetProperty("type").GetString());
        Assert.Equal(imageDataUrl, image.GetProperty("image_url").GetString());
        Assert.Equal("high", image.GetProperty("detail").GetString());

        var saved = db.Query("SELECT title,content_text,screenshot_metadata_json,analysis_json,source_ledger_json,ai_status FROM articles WHERE id=1")[0];
        Assert.Equal("analyzed", saved["ai_status"]);
        Assert.Equal("Fake Google Meet social engineering post", saved["title"]);
        Assert.Equal(transcript, saved["content_text"]);
        using var metadata = JsonDocument.Parse(saved["screenshot_metadata_json"]!);
        Assert.Equal("Anurag", metadata.RootElement.GetProperty("author_name").GetString());
        Assert.Equal("@Malwarehunterr", metadata.RootElement.GetProperty("author_handle").GetString());
        Assert.True(metadata.RootElement.GetProperty("author_verified").GetBoolean());
        var inbox = new InboxModel(db, null!);
        Assert.Equal("Anurag · @Malwarehunterr · X · verified badge shown", inbox.ScreenshotAuthor(saved["screenshot_metadata_json"]));
        inbox.PageContext = new PageContext(new ActionContext(new DefaultHttpContext(), new RouteData(), new PageActionDescriptor()));
        var sourceImage = Assert.IsType<FileContentResult>(inbox.OnGetScreenshot(1));
        Assert.Equal("image/png", sourceImage.ContentType);
        Assert.Equal(imageBytes, sourceImage.FileContents);
        using var ledger = JsonDocument.Parse(saved["source_ledger_json"]!);
        Assert.Equal("screenshot", ledger.RootElement[0].GetProperty("kind").GetString());
        Assert.Equal(transcript, db.Query("SELECT content FROM source_snapshots WHERE article_id=1 AND source_id='src_article'")[0]["content"]);
        var ioc = Assert.Single(IocIndex.Read(db, includeUnapproved: true));
        Assert.Equal("g[.]meet.e2qs0[.]com", ioc.Value);
        Assert.Equal("suspicious", ioc.Role);
        Assert.Equal(4, handler.Requests.Count);
    }

    private sealed class ScreenshotModelHandler(string[] responses) : HttpMessageHandler
    {
        private int _index;
        public List<JsonElement> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            Requests.Add(body.RootElement.Clone());
            var result = responses[_index++];
            var response = JsonSerializer.Serialize(new
            {
                id = $"resp_screenshot_{_index}",
                status = "completed",
                model = "gpt-6-luna",
                output = new[] { new { type = "message", content = new[] { new { type = "output_text", text = result } } } }
            });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class StaticHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }

    private sealed class TestDatabase(string path, AppDatabase database) : IDisposable
    {
        public AppDatabase Database => database;
        public static TestDatabase Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "AggroScreenshotTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            var prior = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR");
            try
            {
                Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", path);
                var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = path }).Environment;
                var db = new AppDatabase(environment);
                db.Initialize();
                return new TestDatabase(path, db);
            }
            finally { Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior); }
        }
        public void Dispose() { database.Dispose(); Directory.Delete(path, true); }
    }
}
