using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.FileProviders;
using ThreatIntelAggro;
using Xunit;

namespace ThreatIntelAggro.Tests;

public sealed class SecurityAndIocTests
{
    [Fact]
    public void GeneratedApiKeyIsUrlSafeAndHas256BitsOfEntropy()
    {
        var key = ApiKeySecurity.Generate();

        Assert.Equal(43, key.Length);
        Assert.Matches("^[A-Za-z0-9_-]+$", key);
    }

    [Fact]
    public void ApiKeyHashIsStableSha256Hex()
    {
        var hash = ApiKeySecurity.Hash("test-key");

        Assert.Equal(64, hash.Length);
        Assert.Equal(ApiKeySecurity.Hash("test-key"), hash);
        Assert.NotEqual(ApiKeySecurity.Hash("other-key"), hash);
    }

    [Fact]
    public void ApiAuthorizationAcceptsCurrentAndUnexpiredPreviousKeysOnly()
    {
        using var temporaryDatabase = TestDatabase.Create();
        var database = temporaryDatabase.Database;
        var current = ApiKeySecurity.Generate();
        var previous = ApiKeySecurity.Generate();
        IocExclusionSettings.Set(database, "api_key_current_hash", ApiKeySecurity.Hash(current));
        IocExclusionSettings.Set(database, "api_key_previous_hash", ApiKeySecurity.Hash(previous));
        IocExclusionSettings.Set(database, "api_key_previous_expires_utc", DateTimeOffset.UtcNow.AddHours(1).ToString("O"));

        Assert.True(ApiKeySecurity.IsAuthorized(database, $"Bearer {current}"));
        Assert.True(ApiKeySecurity.IsAuthorized(database, $"bearer {previous}"));
        Assert.False(ApiKeySecurity.IsAuthorized(database, $"Bearer {ApiKeySecurity.Generate()}"));
        Assert.False(ApiKeySecurity.IsAuthorized(database, $"Basic {current}"));
    }

    [Fact]
    public void ApiAuthorizationRejectsExpiredPreviousKey()
    {
        using var temporaryDatabase = TestDatabase.Create();
        var database = temporaryDatabase.Database;
        var previous = ApiKeySecurity.Generate();
        IocExclusionSettings.Set(database, "api_key_current_hash", ApiKeySecurity.Hash(ApiKeySecurity.Generate()));
        IocExclusionSettings.Set(database, "api_key_previous_hash", ApiKeySecurity.Hash(previous));
        IocExclusionSettings.Set(database, "api_key_previous_expires_utc", DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"));

        Assert.False(ApiKeySecurity.IsAuthorized(database, $"Bearer {previous}"));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("*.example.com")]
    [InlineData("203.0.113.0/24")]
    [InlineData("2001:db8::/32")]
    public void IocExclusionRulesAcceptDomainsAndIpNetworks(string rule) => Assert.True(IocExclusionMatcher.IsValidRule(rule));

    [Theory]
    [InlineData("localhost")]
    [InlineData("*.example.*")]
    [InlineData("192.0.2.1/99")]
    [InlineData("not a domain")]
    public void IocExclusionRulesRejectInvalidValues(string rule) => Assert.False(IocExclusionMatcher.IsValidRule(rule));

    [Fact]
    public void IocMatcherAppliesDomainAndCidrExclusionsAtBoundaries()
    {
        using var temporaryDatabase = TestDatabase.Create();
        var database = temporaryDatabase.Database;
        database.Execute("INSERT INTO ioc_exclusions(value,created_utc) VALUES(?,?)", "example.com", DateTimeOffset.UtcNow.ToString("O"));
        database.Execute("INSERT INTO ioc_exclusions(value,created_utc) VALUES(?,?)", "203.0.113.0/24", DateTimeOffset.UtcNow.ToString("O"));
        var matcher = IocExclusionMatcher.Load(database);

        Assert.True(matcher.Excludes("domain", "sub.example.com", null));
        Assert.True(matcher.Excludes("ip", "203.0.113.255", null));
        Assert.False(matcher.Excludes("ip", "203.0.114.1", null));
        Assert.False(matcher.Excludes("domain", "notexample.com", null));
    }

    private sealed class TestDatabase : IDisposable
    {
        private readonly string _directory;
        private readonly AppDatabase _database;
        private readonly string? _priorDataDirectory;

        private TestDatabase(string directory, AppDatabase database, string? priorDataDirectory)
        {
            _directory = directory;
            _database = database;
            _priorDataDirectory = priorDataDirectory;
        }

        public AppDatabase Database => _database;

        public static TestDatabase Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "ThreatIntelAggro.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var prior = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR");
            Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", directory);
            try
            {
                var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = directory }).Environment;
                var database = new AppDatabase(environment);
                database.Initialize();
                return new TestDatabase(directory, database, prior);
            }
            catch
            {
                Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior);
                Directory.Delete(directory, recursive: true);
                throw;
            }
            finally
            {
                Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", prior);
            }
        }

        public void Dispose()
        {
            _database.Dispose();
            Directory.Delete(_directory, recursive: true);
            Environment.SetEnvironmentVariable("AGGRO_DATA_DIR", _priorDataDirectory);
        }
    }
}
