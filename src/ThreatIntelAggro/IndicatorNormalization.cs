using System.Net;

namespace ThreatIntelAggro;

public static class IndicatorNormalization
{
    // Only known, deterministic transformations are accepted; model-provided values
    // are never trusted to identify a different indicator.
    public static bool Matches(string? type, string value, string? normalized)
    {
        if (normalized is null) return true;
        var original = Defang(value.Trim());
        var candidate = Defang(normalized.Trim());
        if (original.Length == 0 || candidate.Length == 0) return false;
        switch (type?.ToLowerInvariant())
        {
            case "ipv4":
            case "ipv6":
                return IPAddress.TryParse(original.Trim('[', ']'), out var first) && IPAddress.TryParse(candidate.Trim('[', ']'), out var second) && first.Equals(second);
            case "domain":
            case "md5":
            case "sha1":
            case "sha256":
                return original.Equals(candidate, StringComparison.OrdinalIgnoreCase);
            case "url":
                return Uri.TryCreate(original, UriKind.Absolute, out var firstUri) && Uri.TryCreate(candidate, UriKind.Absolute, out var secondUri) &&
                    firstUri.Scheme is "http" or "https" && secondUri.Scheme is "http" or "https" &&
                    string.IsNullOrEmpty(firstUri.UserInfo) && string.IsNullOrEmpty(secondUri.UserInfo) &&
                    firstUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped).Equals(secondUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped), StringComparison.Ordinal);
            case "email":
                var firstAt = original.LastIndexOf('@');
                var secondAt = candidate.LastIndexOf('@');
                return firstAt > 0 && secondAt > 0 && original[..firstAt].Equals(candidate[..secondAt], StringComparison.Ordinal) && original[(firstAt + 1)..].Equals(candidate[(secondAt + 1)..], StringComparison.OrdinalIgnoreCase);
            default:
                return value.Trim().Equals(normalized.Trim(), StringComparison.Ordinal);
        }
    }

    private static string Defang(string value) => value
        .Replace("[.]", ".", StringComparison.OrdinalIgnoreCase)
        .Replace("(.)", ".", StringComparison.OrdinalIgnoreCase)
        .Replace("[:]", ":", StringComparison.OrdinalIgnoreCase)
        .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase)
        .Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase);
}
