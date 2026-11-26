using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ThreatIntelAggro;

public sealed class HomeFeedRoute : IDisposable
{
    public const string DefaultSetting = "feed_default_fetch_route";

    private readonly Uri? _proxy;
    private readonly HttpClient? _githubClient;
    private readonly SafePublicFetcher? _fetcher;

    public HomeFeedRoute(IConfiguration configuration)
    {
        var address = configuration["AGGRO_HOME_FEED_PROXY"];
        if (string.IsNullOrWhiteSpace(address)) return;
        if (!Uri.TryCreate(address, UriKind.Absolute, out var proxy) || proxy.Scheme != Uri.UriSchemeHttp ||
            proxy.UserInfo.Length != 0 || proxy.PathAndQuery != "/" || proxy.Fragment.Length != 0)
            throw new InvalidOperationException("AGGRO_HOME_FEED_PROXY must be an HTTP proxy address with no credentials or path.");

        _proxy = proxy;
        _fetcher = new SafePublicFetcher(CreateHandler());
        _githubClient = new HttpClient(CreateHandler()) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public static string DefaultRoute(AppDatabase database) =>
        IocExclusionSettings.Get(database, DefaultSetting) == "home" ? "home" : "direct";

    public async Task<bool> CheckAvailabilityAsync(CancellationToken cancellationToken)
    {
        if (_proxy is null) return false;

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            await using var tunnel = await OpenTunnelAsync(IPAddress.Parse("1.1.1.1"), 443, deadline.Token);
            return true;
        }
        catch (Exception e) when (e is IOException or SocketException or HttpRequestException ||
                                  e is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    public Task<byte[]> GetAsync(string url, int maxBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var fetcher = _fetcher ?? throw new InvalidOperationException("Home exit node is not configured.");
        return FetchAsync();

        async Task<byte[]> FetchAsync()
        {
            try { return await fetcher.GetAsync(url, maxBytes, timeout, cancellationToken); }
            catch (TimeoutException e) { throw new TimeoutException("Home exit node fetch timed out.", e); }
        }
    }

    public GitHubAdvisoryReader CreateGitHubReader() =>
        new(_githubClient ?? throw new InvalidOperationException("Home exit node is not configured."));

    private SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectCallback = async (context, token) =>
        {
            var target = context.DnsEndPoint;
            try
            {
                // The proxy receives a vetted numeric address. HttpClient retains the original hostname for HTTP and TLS.
                var addresses = await SafePublicFetcher.ResolvePublicAddressesAsync(target, token);
                foreach (var address in addresses)
                {
                    try { return await OpenTunnelAsync(address, target.Port, token); }
                    catch (TunnelRejectedException) when (!address.Equals(addresses[^1])) { }
                }
                throw new InvalidOperationException("The DNS safety check returned no usable addresses.");
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                throw new HttpRequestException($"Home exit node fetch failed. {e.Message}", e);
            }
        }
    };

    private async Task<Stream> OpenTunnelAsync(IPAddress address, int port, CancellationToken cancellationToken)
    {
        var proxy = _proxy!;
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(proxy.IdnHost, proxy.Port, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var stream = new NetworkStream(socket, ownsSocket: true);
        try
        {
            var endpoint = new IPEndPoint(address, port).ToString();
            var request = Encoding.ASCII.GetBytes($"CONNECT {endpoint} HTTP/1.1\r\nHost: {endpoint}\r\n\r\n");
            await stream.WriteAsync(request, cancellationToken);
            var response = new byte[8192];
            var length = 0;
            while (length < response.Length)
            {
                var read = await stream.ReadAsync(response.AsMemory(length), cancellationToken);
                if (read == 0) break;
                length += read;
                if (!response.AsSpan(0, length).EndsWith("\r\n\r\n"u8)) continue;

                var lineEnd = response.AsSpan(0, length).IndexOf("\r\n"u8);
                var status = Encoding.ASCII.GetString(response, 0, lineEnd).Split(' ', 3);
                if (status.Length >= 2 && status[0] is "HTTP/1.0" or "HTTP/1.1" && status[1] == "200")
                    return stream;
                throw new TunnelRejectedException(status.Length >= 2 && int.TryParse(status[1], out var code)
                    ? $"Proxy returned HTTP {code} while opening the tunnel."
                    : "Proxy returned an invalid tunnel response.");
            }
            throw new HttpRequestException("Proxy returned incomplete or oversized tunnel headers.");
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
    }

    private sealed class TunnelRejectedException(string message) : HttpRequestException(message);

    public void Dispose()
    {
        _fetcher?.Dispose();
        _githubClient?.Dispose();
    }
}
