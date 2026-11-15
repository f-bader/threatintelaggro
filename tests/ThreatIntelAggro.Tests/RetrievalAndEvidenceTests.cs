using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using ThreatIntelAggro;
using Xunit;

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
    public void RejectsNonPublicAddresses(string address) => Assert.False(SafePublicFetcher.IsPublic(IPAddress.Parse(address)));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
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
        Assert.Contains("non-public", error.ToString());
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
        {"schema_version":"1.0","language":"en","category":"Existing Research","category_rationale":"fixture",
         "summary":{"headline":"fixture","overview":"fixture","key_findings":[]},
         "iocs":[{"type":"domain","value":"evil.example","normalized_value":"evil.example","role":"malicious","context":"observed","confidence":"high","basis":"source_reported","evidence":[{"source_id":"src_article","locator":"paragraph 1","excerpt":"Malicious domain evil.example was observed."}]}],
         "references":[{"source_id":"src_article","url":"https://example.com/","title":"Fixture","kind":"original","inspection_status":"fetched","relevance":"original"}],
         "mitre_mappings":[],"industries":[],"threat_actors":[],"vendors":[],"products":[],"malware":[],"campaigns":[],"vulnerabilities":[],"targeted_countries":[],
         "detection_assessment":{"potential":"uncertain","reason":"fixture","evidence":[]},"coverage":{"limitations":[],"uninspected_source_ids":[],"conflicting_claims":[]}}
        """)!;
        ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema);
        article["iocs"]![0]!["evidence"]![0]!["excerpt"] = "fabricated evil.example";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["iocs"]![0]!["evidence"]![0]!["excerpt"] = "Malicious domain evil.example was observed.";
        article["references"]![0]!["url"] = "https://attacker.example/";
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
        article["references"]![0]!["url"] = "https://example.com/";
        article["iocs"]![0]!["evidence"] = new JsonArray();
        Assert.Throws<InvalidOperationException>(() => ArticleEvidenceValidator.Validate(article.ToJsonString(), sources, schema));
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
