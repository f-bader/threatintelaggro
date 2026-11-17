using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using ThreatIntelAggro;
using Xunit;
using YamlDotNet.RepresentationModel;

namespace ThreatIntelAggro.Tests;

public sealed class RetrievalAndEvidenceTests
{
    [Theory]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("127.0.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("2001:db8::1")]
    [InlineData("64:ff9b::a00:1")]
    [InlineData("2002:0a00:0001::")]
    [InlineData("2001::1")]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.2.1")]
    public void RejectsNonPublicAddresses(string address) => Assert.False(SafePublicFetcher.IsPublic(IPAddress.Parse(address)));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("192.0.78.137")]
    [InlineData("192.0.78.197")]
    public void AcceptsPublicAddresses(string address) => Assert.True(SafePublicFetcher.IsPublic(IPAddress.Parse(address)));

    [Fact]
    public async Task BlocksRedirectToMappedPrivateAddress()
    {
        using var fetcher = new SafePublicFetcher(new Handler(_ => new HttpResponseMessage(HttpStatusCode.Redirect) { Headers = { Location = new Uri("http://[::ffff:10.0.0.1]/") } }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fetcher.GetAsync("https://example.com/", 100, TimeSpan.FromSeconds(1), CancellationToken.None));
    }

    [Fact]
    public async Task ProductionConnectionRejectsDnsResolvingToLoopback()
    {
        using var fetcher = new SafePublicFetcher();
        var error = await Assert.ThrowsAnyAsync<Exception>(() => fetcher.GetAsync("http://localhost/", 100, TimeSpan.FromSeconds(3), CancellationToken.None));
        Assert.Contains("DNS safety check blocked", error.ToString());
        Assert.Contains("Rejected addresses", error.ToString());
    }

    [Fact]
    public async Task HttpFailuresIncludeResponseDiagnosticsWithoutQuerySecrets()
    {
        using var fetcher = new SafePublicFetcher(new Handler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent("automated requests are forbidden")
            };
            response.Headers.TryAddWithoutValidation("x-request-id", "request-123");
            response.Headers.Server.ParseAdd("fixture-server");
            return response;
        }));

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => fetcher.GetAsync("https://example.com/feed/?token=private", 100, TimeSpan.FromSeconds(1), CancellationToken.None));

        Assert.Equal(HttpStatusCode.Forbidden, error.StatusCode);
        Assert.Contains("HTTP 403 Forbidden", error.Message);
        Assert.Contains("https://example.com/feed/", error.Message);
        Assert.Contains("request-123", error.Message);
        Assert.Contains("automated requests are forbidden", error.Message);
        Assert.DoesNotContain("token=private", error.Message);
    }

    [Fact]
    public async Task StopsOversizedStreamingResponse()
    {
        using var fetcher = new SafePublicFetcher(new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new UnseekableStream(new byte[1000])) }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fetcher.GetAsync("https://example.com/", 100, TimeSpan.FromSeconds(1), CancellationToken.None));
    }

    [Fact]
    public async Task BodyReadHasDeadline()
    {
        using var fetcher = new SafePublicFetcher(new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new SlowStream()) }));
        await Assert.ThrowsAsync<TimeoutException>(() => fetcher.GetAsync("https://example.com/", 100, TimeSpan.FromMilliseconds(50), CancellationToken.None));
    }

    [Fact]
    public void EvidenceMustMatchSourceAndReferenceLedger()
    {
        var schema = (JsonObject)typeof(AnalysisService).GetMethod("ArticleSchema", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, null)!;
        var sources = JsonNode.Parse("""[{"source_id":"src_article","title":"Fixture","url":"https://example.com/","kind":"original","inspection_status":"fetched","content":"Malicious domain evil.example was observed."}]""")!.AsArray();
        var article = JsonNode.Parse("""
        {"schema_version":"1.2","language":"en","category":"Existing Research","category_rationale":"fixture",
         "summary":{"headline":"fixture","overview":"fixture","key_findings":[],"evidence":[{"source_id":"src_article","locator":"paragraph 1","excerpt":"Malicious domain evil.example was observed."}]},
         "iocs":[{"type":"domain","value":"evil.example","normalized_value":"evil.example","role":"malicious","context":"observed","confidence":"high","basis":"source_reported","evidence":[{"source_id":"src_article","locator":"paragraph 1","excerpt":"Malicious domain evil.example was observed."}]}],
         "references":[{"source_id":"src_article","url":"https://example.com/","title":"Fixture","kind":"original","inspection_status":"fetched","relevance":"original"}],
         "mitre_mappings":[],"industries":[],"threat_actors":[],"vendors":[],"products":[],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],
         "detection_assessment":{"potential":"uncertain","reason":"fixture","evidence":[]},"coverage":{"limitations":[],"uninspected_source_ids":[],"conflicting_claims":[]}}
        """)!;
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        article["summary"]!["evidence"]![0]!["excerpt"] = "malicious domain evil.example was observed.";
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        article["summary"]!["evidence"]![0]!["excerpt"] = "Malicious domain evil.example was observed.";
        sources[0]!["inspection_status"] = "search_excerpt";
        article["references"]![0]!["inspection_status"] = "search_excerpt";
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        sources[0]!["inspection_status"] = "inaccessible";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        sources[0]!["inspection_status"] = "fetched";
        article["references"]![0]!["inspection_status"] = "fetched";
        var summaryEvidence = article["summary"]!["evidence"]!.DeepClone();
        article["summary"]!["evidence"] = new JsonArray();
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["summary"]!["evidence"] = summaryEvidence;
        article["iocs"]![0]!["evidence"]![0]!["excerpt"] = "fabricated evil.example";
        Assert.ThrowsAny<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["iocs"]![0]!["evidence"]![0]!["excerpt"] = "Malicious domain evil.example was observed.";
        article["references"]![0]!["url"] = "https://attacker.example/";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["references"]![0]!["url"] = "https://example.com/";
        article["iocs"]![0]!["normalized_value"] = "unrelated.example";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["iocs"]![0]!["normalized_value"] = "evil.example";
        const string defangedEvidence = "Reported indicators: g[.]meet.e2qs0[.]com and hxxps://g[.]meet.e2qs0[.]com/app.js";
        sources[0]!["content"] = defangedEvidence;
        article["summary"]!["evidence"]![0]!["excerpt"] = defangedEvidence;
        article["iocs"]![0]!["value"] = "g[.]meet.e2qs0[.]com";
        article["iocs"]![0]!["normalized_value"] = null;
        article["iocs"]![0]!["context"] = "reported domain";
        article["iocs"]![0]!["evidence"]![0]!["excerpt"] = defangedEvidence;
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        article["iocs"]![0]!["type"] = "url";
        article["iocs"]![0]!["value"] = "hxxps://g[.]meet.e2qs0[.]com/app.js";
        article["iocs"]![0]!["context"] = "reported URL";
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        sources[0]!["content"] = "Malicious domain evil.example was observed.";
        article["summary"]!["evidence"]![0]!["excerpt"] = "Malicious domain evil.example was observed.";
        article["iocs"]![0]!["type"] = "domain";
        article["iocs"]![0]!["value"] = "evil.example";
        article["iocs"]![0]!["normalized_value"] = "evil.example";
        article["iocs"]![0]!["context"] = "observed";
        article["iocs"]![0]!["evidence"]![0]!["excerpt"] = "Malicious domain evil.example was observed.";
        article["iocs"]![0]!["role"] = "malware";
        var roleError = Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        Assert.Contains("role", roleError.Message);
        Assert.Contains("invalid value", roleError.Message);
        article["iocs"]![0]!["role"] = "malicious";
        article["iocs"]![0]!["evidence"] = new JsonArray();
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
    }

    [Fact]
    public void EvidenceMismatchCanBeRepairedOnlyWithAnExactSourceExcerpt()
    {
        var sources = JsonNode.Parse("""[{"source_id":"src_article","inspection_status":"fetched","content":"The user's process wrote a file — then exited."}]""")!.AsArray();
        var output = JsonNode.Parse("""{"summary":{"evidence":[{"source_id":"src_article","excerpt":"the user’s process wrote a file-then crashed."}]}}""")!.ToJsonString();
        var mismatches = ArticleEvidenceValidator.FindEvidenceMismatches(output, sources);
        var mismatch = Assert.Single(mismatches);
        Assert.Equal("/summary/evidence/0", mismatch.Path);

        var repaired = ArticleEvidenceValidator.ApplyEvidenceCorrections(output, sources, new JsonArray(
            new JsonObject { ["path"] = mismatch.Path, ["source_id"] = mismatch.SourceId, ["excerpt"] = "The user's process wrote a file — then exited." }));
        Assert.Empty(ArticleEvidenceValidator.FindEvidenceMismatches(repaired, sources));

        var ignored = ArticleEvidenceValidator.ApplyEvidenceCorrections(output, sources, new JsonArray(
            new JsonObject { ["path"] = mismatch.Path, ["source_id"] = mismatch.SourceId, ["excerpt"] = "invented citation" }));
        Assert.Equal(output, ignored);
    }

    [Fact]
    public void DetectionBehaviorsRequireVerifiableSourceEvidence()
    {
        var schema = (JsonObject)typeof(AnalysisService).GetMethod("DetectionSchema", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, null)!;
        var sources = JsonNode.Parse("""[{"source_id":"src_article","inspection_status":"fetched","content":"The user's process wrote a file."}]""")!.AsArray();
        var detection = JsonNode.Parse("""
        {"schema_version":"1.1","outcome":"drafts_generated","reason":"fixture","coverage":[],"detections":[{"local_key":"test","alert_title":"test","description":"test","severity":"low","rationale":"test","kql":"DeviceEvents | take 1","tactic":"Execution","techniques":[],"behaviors":[{"description":"file write","basis":"source_reported","confidence":"high","evidence":[{"source_id":"src_article","locator":"paragraph 1","excerpt":"The user's process wrote a file."}]}],"source_ids":["src_article"],"playbook":{"title":"test","triage_steps":[],"investigation_steps":[],"response_options":[]},"mitre_mappings":[],"telemetry":{"tables":[],"required_columns":[],"assumptions":[],"known_gaps":[]}}]}
        """)!;
        ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema);
        detection["detections"]![0]!["behaviors"]![0]!["evidence"]![0]!["excerpt"] = "the user’s process wrote a file.";
        ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema);
        detection["detections"]![0]!["behaviors"]![0]!["evidence"]![0]!["excerpt"] = "The user\u0019s process wrote a file.";
        ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema);
        var severitySchema = schema["properties"]!["detections"]!["items"]!["properties"]!["severity"]!;
        Assert.Equal(new[] { "informational", "low", "medium", "high" }, severitySchema["enum"]!.AsArray().Select(x => x!.GetValue<string>()));
        detection["detections"]![0]!["severity"] = "Medium";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema));
        detection["detections"]![0]!["severity"] = "low";
        sources[0]!["inspection_status"] = "search_excerpt";
        ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema);
        sources[0]!["inspection_status"] = "inaccessible";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema));
        sources[0]!["inspection_status"] = "fetched";
        detection["detections"]![0]!["behaviors"]![0]!["evidence"]![0]!["source_id"] = "invented";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema));
        detection["detections"]![0]!["behaviors"]![0]!["evidence"]![0]!["source_id"] = "src_article";
        detection["detections"]![0]!["source_ids"] = new JsonArray();
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema));
        detection["detections"]![0]!["source_ids"] = new JsonArray("src_article");
        detection["outcome"] = "no_supported_detection";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema));
        detection["outcome"] = "drafts_generated";
        detection["detections"]!.AsArray().Add(detection["detections"]![0]!.DeepClone());
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.ValidateDetection(detection.ToJsonString(), sources, schema));
    }

    [Theory]
    [InlineData("domain", "safe.example", "evil.example", false)]
    [InlineData("domain", "evil[.]example", "evil.example", true)]
    [InlineData("url", "hxxps://evil[.]example/Path", "https://evil.example/Path", true)]
    [InlineData("url", "https://evil.example/Path", "https://evil.example/path", false)]
    [InlineData("ipv4", "192.0.2.1", "192.0.2.2", false)]
    [InlineData("ipv6", "2001:db8::1", "2001:0db8:0:0:0:0:0:1", true)]
    [InlineData("file_path", "C:\\safe.exe", "C:\\evil.exe", false)]
    public void NormalizedIndicatorsMustMatchTheirSource(string type, string original, string normalized, bool valid)
        => Assert.Equal(valid, IndicatorNormalization.Matches(type, original, normalized));

    [Theory]
    [InlineData("DeviceEvents | take 1")]
    [InlineData("DeviceEvents\n| where ActionType == \"Test\"\n")]
    public void DetectionYamlUsesPinnedSchemaAndPreservesQuery(string query)
    {
        var detection = new Dictionary<string, string?>
        {
            ["guid"] = "8f3e2179-5b53-45eb-8e12-f74b653c743f", ["alert_title"] = "Title: \"quoted\"\nnext",
            ["description"] = "Multiline\nDescription", ["severity"] = "high", ["kql"] = query,
            ["xdr_tactic"] = "Execution", ["xdr_techniques_json"] = "[\"T1059\"]"
        };
        var yaml = DetectionYaml.Export(detection);
        var parsed = new YamlStream();
        parsed.Load(new StringReader(yaml));
        var root = Assert.IsType<YamlMappingNode>(Assert.Single(parsed.Documents).RootNode);
        Assert.Equal(query, Assert.IsType<YamlScalarNode>(root.Children[new YamlScalarNode("queryText")]).Value);
        Assert.Equal("disabled", Assert.IsType<YamlScalarNode>(root.Children[new YamlScalarNode("status")]).Value);
        Assert.Equal(detection["alert_title"], Assert.IsType<YamlScalarNode>(root.Children[new YamlScalarNode("ruleName")]).Value);
    }

    [Fact]
    public void DetectionYamlRequiresSchemaCompatibleTacticAndTechnique()
    {
        var detection = new Dictionary<string, string?> { ["guid"] = "8f3e2179-5b53-45eb-8e12-f74b653c743f", ["alert_title"] = "test", ["description"] = "test", ["severity"] = "medium", ["kql"] = "DeviceEvents | take 1", ["xdr_tactic"] = "", ["xdr_techniques_json"] = "[]" };
        Assert.Throws<InvalidOperationException>(() => DetectionYaml.Export(detection));
        detection["xdr_tactic"] = "Execution";
        detection["xdr_techniques_json"] = "[\"not-a-technique\"]";
        Assert.Throws<InvalidOperationException>(() => DetectionYaml.Export(detection));
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(response(request));
    }
    private sealed class UnseekableStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream inner = new(bytes);
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => inner.ReadAsync(buffer, token);
        public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
    private sealed class SlowStream : Stream
    {
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) { await Task.Delay(Timeout.InfiniteTimeSpan, token); return 0; }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
        public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
