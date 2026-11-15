using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace ThreatIntelAggro;

public static class ForwardedProxyPolicy
{
    public static void Configure(ForwardedHeadersOptions options, string[] trustedProxyIps)
    {
        options.ForwardedHeaders = trustedProxyIps.Length == 0 ? ForwardedHeaders.None : ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = 1;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var proxyIp in trustedProxyIps)
        {
            if (!IPAddress.TryParse(proxyIp, out var address))
                throw new InvalidOperationException($"AGGRO_TRUSTED_PROXY_IPS contains an invalid IP address: {proxyIp}");
            options.KnownProxies.Add(address);
        }
    }
}
