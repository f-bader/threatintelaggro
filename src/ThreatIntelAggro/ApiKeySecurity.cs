using System.Security.Cryptography;
using System.Text;

namespace ThreatIntelAggro;

public static class ApiKeySecurity
{
    public static string Generate() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .Replace('+', '-')
        .Replace('/', '_')
        .TrimEnd('=');

    public static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public static bool IsAuthorized(AppDatabase database, string? authorizationHeader)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader)) return false;
        var separator = authorizationHeader.IndexOf(' ');
        if (separator <= 0 || !authorizationHeader[..separator].Equals("Bearer", StringComparison.OrdinalIgnoreCase)) return false;
        var token = authorizationHeader[(separator + 1)..].Trim();
        if (token.Length == 0) return false;

        var candidateHash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        var currentHash = IocExclusionSettings.Get(database, "api_key_current_hash");
        if (Matches(candidateHash, currentHash)) return true;

        var previousHash = IocExclusionSettings.Get(database, "api_key_previous_hash");
        var expiresText = IocExclusionSettings.Get(database, "api_key_previous_expires_utc");
        return DateTimeOffset.TryParse(expiresText, out var expires) && expires > DateTimeOffset.UtcNow && Matches(candidateHash, previousHash);
    }

    private static bool Matches(byte[] candidateHash, string storedHash)
    {
        if (storedHash.Length != 64) return false;
        try
        {
            var expectedHash = Convert.FromHexString(storedHash);
            return expectedHash.Length == candidateHash.Length && CryptographicOperations.FixedTimeEquals(candidateHash, expectedHash);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
