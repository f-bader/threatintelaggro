using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public sealed class IocExclusionMatcher
{
    private readonly string[] _domains;
    private readonly (IPAddress Network, int Prefix)[] _networks;

    private IocExclusionMatcher(IEnumerable<string> rules)
    {
        var domains = new List<string>();
        var networks = new List<(IPAddress, int)>();
        foreach (var raw in rules)
        {
            var rule = Normalize(raw);
            if (rule.Length == 0) continue;
            if (TryNetwork(rule, out var network, out var prefix)) networks.Add((network, prefix));
            else domains.Add(rule);
        }
        _domains = domains.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _networks = networks.ToArray();
    }

    public static IocExclusionMatcher Load(AppDatabase database)
    {
        var rules = database.Query("SELECT value FROM ioc_exclusions").Select(x => x["value"] ?? "").ToList();
        var enabled = database.Query("SELECT value FROM app_settings WHERE key='exclude_m365_endpoints'").FirstOrDefault()?["value"] == "true";
        if (enabled)
        {
            var data = database.Query("SELECT value FROM app_settings WHERE key='m365_endpoints_json'").FirstOrDefault()?["value"];
            if (!string.IsNullOrWhiteSpace(data))
            {
                try
                {
                    using var document = JsonDocument.Parse(data);
                    foreach (var key in new[] { "urls", "ips" })
                        if (document.RootElement.TryGetProperty(key, out var list) && list.ValueKind == JsonValueKind.Array)
                            rules.AddRange(list.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? ""));
                }
                catch (JsonException) { }
            }
        }
        return new IocExclusionMatcher(rules);
    }

    public static bool IsValidRule(string value)
    {
        var rule = Normalize(value);
        if (rule.Length is < 3 or > 253) return false;
        if (rule.Contains('/') && TryNetwork(rule, out _, out _)) return true;
        if (IPAddress.TryParse(rule, out _)) return true;
        var domain = rule.StartsWith("*.", StringComparison.Ordinal) ? rule[2..] : rule;
        return !domain.Contains('*') && domain.Contains('.') && Uri.CheckHostName(domain) == UriHostNameType.Dns;
    }

    public bool Excludes(string type, string value, string? normalizedValue)
    {
        foreach (var candidate in new[] { value, normalizedValue ?? "" }.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            var normalized = Normalize(candidate);
            if (TryExtractIp(normalized, out var ip) && _networks.Any(x => InNetwork(ip, x.Network, x.Prefix))) return true;
            var domain = ExtractDomain(normalized);
            if (domain is not null && _domains.Any(rule => DomainMatches(domain, rule))) return true;
        }
        return false;
    }

    private static string Normalize(string value) => value.Trim().TrimEnd('.')
        .Replace("[.]", ".", StringComparison.OrdinalIgnoreCase)
        .Replace("(.)", ".", StringComparison.OrdinalIgnoreCase)
        .Replace("[:]", ":", StringComparison.OrdinalIgnoreCase)
        .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase)
        .Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractDomain(string value)
    {
        var candidate = value;
        if (candidate.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) candidate = candidate[4..];
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var absolute) && absolute.Scheme is "http" or "https") candidate = absolute.Host;
        else if (candidate.Contains('/') || candidate.Contains(':'))
        {
            if (Uri.TryCreate("https://" + candidate, UriKind.Absolute, out var withScheme)) candidate = withScheme.Host;
        }
        candidate = candidate.Trim().TrimEnd('.');
        if (candidate.Length > 253 || candidate.Contains('*') || !candidate.Contains('.') || Uri.CheckHostName(candidate) != UriHostNameType.Dns) return null;
        return candidate;
    }

    private static bool TryExtractIp(string value, out IPAddress ip)
    {
        var candidate = value;
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var absolute) && absolute.Scheme is "http" or "https") candidate = absolute.Host;
        return IPAddress.TryParse(candidate.Trim('[', ']'), out ip!);
    }

    private static bool DomainMatches(string domain, string rule)
    {
        if (rule.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = rule[2..];
            if (domain.Equals(suffix, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) return true;
        }
        if (rule.Contains('*')) return Regex.IsMatch(domain, "^" + Regex.Escape(rule).Replace("\\*", ".*") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return domain.Equals(rule, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + rule, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryNetwork(string rule, out IPAddress network, out int prefix)
    {
        network = IPAddress.None; prefix = 0;
        var parts = rule.Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var parsedNetwork) || parsedNetwork is null) return false;
        network = parsedNetwork;
        var bitCount = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (parts.Length == 1) { prefix = bitCount; return true; }
        return int.TryParse(parts[1], out prefix) && prefix >= 0 && prefix <= bitCount;
    }

    private static bool InNetwork(IPAddress address, IPAddress network, int prefix)
    {
        if (address.AddressFamily != network.AddressFamily)
        {
            if (address.IsIPv4MappedToIPv6 && network.AddressFamily == AddressFamily.InterNetwork) address = address.MapToIPv4();
            else if (network.IsIPv4MappedToIPv6 && address.AddressFamily == AddressFamily.InterNetwork)
            {
                // Compare in IPv6 space so prefixes shorter than /96 retain their meaning.
                address = address.MapToIPv6();
            }
            else return false;
        }
        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        var wholeBytes = prefix / 8;
        var remainingBits = prefix % 8;
        for (var i = 0; i < wholeBytes; i++) if (addressBytes[i] != networkBytes[i]) return false;
        if (remainingBits == 0) return true;
        var mask = (byte)(0xff << (8 - remainingBits));
        return (addressBytes[wholeBytes] & mask) == (networkBytes[wholeBytes] & mask);
    }
}
