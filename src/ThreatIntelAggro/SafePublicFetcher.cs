using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ThreatIntelAggro;

// A dedicated client for untrusted URLs. DNS is checked inside the connection callback,
// so the address checked is the address actually used by the socket.
public sealed class SafePublicFetcher : IDisposable
{
    private readonly HttpClient _client;
    public SafePublicFetcher() : this(CreateHandler()) { }
    public SafePublicFetcher(HttpMessageHandler handler) => _client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

    private static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectCallback = async (context, token) =>
        {
            var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, token);
            var rejectedAddresses = addresses.Where(ip => !IsPublic(ip)).ToArray();
            if (addresses.Length == 0 || rejectedAddresses.Length > 0)
            {
                var resolved = addresses.Length == 0 ? "<none>" : string.Join(", ", addresses.Select(DescribeAddress));
                var rejected = rejectedAddresses.Length == 0 ? "<none>" : string.Join(", ", rejectedAddresses.Select(ip => ip.ToString()));
                throw new InvalidOperationException($"DNS safety check blocked '{FormatHost(context.DnsEndPoint.Host, context.DnsEndPoint.Port)}'. Resolved addresses: [{resolved}]. Rejected addresses: [{rejected}].");
            }
            Exception? lastError = null;
            foreach (var address in addresses)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch (Exception ex) when (ex is SocketException)
                {
                    socket.Dispose(); lastError = ex;
                }
                catch { socket.Dispose(); throw; }
            }
            throw new HttpRequestException($"Unable to connect to '{FormatHost(context.DnsEndPoint.Host, context.DnsEndPoint.Port)}'. Tried public addresses: [{string.Join(", ", addresses.Select(ip => ip.ToString()))}]. Last socket error: {lastError?.Message ?? "none"}.", lastError);
        }
    };

    private static string DescribeAddress(IPAddress address) => $"{address} ({(IsPublic(address) ? "public" : "blocked")})";

    private static string FormatHost(string host, int port) => $"{(host.Contains(':') ? $"[{host}]" : host)}:{port}";

    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] is 0 or 10 or 127 or >= 224 ||
                (b[0] == 100 && b[1] is >= 64 and <= 127) ||
                (b[0] == 169 && b[1] == 254) || (b[0] == 172 && b[1] is >= 16 and <= 31) ||
                (b[0] == 192 && (b[1] == 168 || b[1] == 0 || (b[1] == 88 && b[2] == 99))) ||
                (b[0] == 198 && (b[1] is 18 or 19 || (b[1] == 51 && b[2] == 100))) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113));
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        var v6 = address.GetAddressBytes();
        // Reject IPv6 transition and special-purpose ranges as well as non-global addresses.
        return (v6[0] & 0xe0) == 0x20 && !(v6[0] == 0x20 && v6[1] == 0x02) &&
            !(v6[0] == 0x3f && v6[1] == 0xff && (v6[2] & 0xf0) == 0) &&
            !(v6[0] == 0x20 && v6[1] == 0x01 &&
                ((v6[2] == 0x0d && v6[3] == 0xb8) || (v6[2] == 0x00 && v6[3] <= 0x1f)));
    }

    public async Task<byte[]> GetAsync(string url, int maxBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            var current = new Uri(url);
            for (var hop = 0; hop <= 5; hop++)
            {
                ValidateUri(current);
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                request.Headers.UserAgent.ParseAdd("ThreatIntelAggro/0.1");
                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is not null)
                {
                    current = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(current, response.Headers.Location);
                    continue;
                }
                if (!response.IsSuccessStatusCode)
                {
                    var bodySnippet = await ReadDiagnosticSnippetAsync(response.Content, deadline.Token);
                    var contentType = response.Content.Headers.ContentType?.ToString() ?? "unknown";
                    var server = response.Headers.Server.ToString();
                    var requestId = GetDiagnosticHeader(response, "x-request-id", "request-id", "cf-ray", "x-amz-cf-id");
                    var details = $"Source returned HTTP {(int)response.StatusCode} {response.ReasonPhrase} for {request.Method.Method} {DiagnosticUrl(current)}. Content-Type: {contentType}.";
                    if (!string.IsNullOrWhiteSpace(server)) details += $" Server: {server}.";
                    if (!string.IsNullOrWhiteSpace(requestId)) details += $" Request ID: {requestId}.";
                    if (!string.IsNullOrWhiteSpace(bodySnippet)) details += $" Response snippet: {bodySnippet}";
                    throw new HttpRequestException(details, null, response.StatusCode);
                }
                if (response.Content.Headers.ContentLength > maxBytes) throw new InvalidOperationException("Source exceeds the size limit.");
                await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
                using var output = new MemoryStream();
                var buffer = new byte[16384];
                int read;
                while ((read = await stream.ReadAsync(buffer, deadline.Token)) != 0)
                {
                    if (output.Length + read > maxBytes) throw new InvalidOperationException("Source exceeds the size limit.");
                    output.Write(buffer, 0, read);
                }
                return output.ToArray();
            }
            throw new InvalidOperationException("Source redirect limit exceeded.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Source retrieval exceeded its deadline.");
        }
    }

    private static void ValidateUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidOperationException("Only public HTTP/HTTPS sources without credentials are allowed.");
        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && !IsPublic(ip))
            throw new InvalidOperationException("Private and reserved source addresses are blocked.");
    }

    private static string DiagnosticUrl(Uri uri)
    {
        var safe = new UriBuilder(uri) { Query = "", Fragment = "" }.Uri;
        return safe.AbsoluteUri;
    }

    private static string GetDiagnosticHeader(HttpResponseMessage response, params string[] names)
    {
        foreach (var name in names)
            if (response.Headers.TryGetValues(name, out var values)) return Limit(string.Join(",", values), 160);
        return "";
    }

    private static async Task<string> ReadDiagnosticSnippetAsync(HttpContent content, CancellationToken cancellationToken)
    {
        const int maxBytes = 1200;
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[maxBytes];
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (count == 0) break;
            read += count;
        }
        var snippet = Encoding.UTF8.GetString(buffer, 0, read);
        snippet = string.Concat(snippet.Select(c => char.IsControl(c) && c is not '\t' ? ' ' : c));
        snippet = string.Join(' ', snippet.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return Limit(snippet, 800);
    }

    private static string Limit(string value, int max) => value.Length <= max ? value : value[..max] + " [truncated]";
    public void Dispose() => _client.Dispose();
}
