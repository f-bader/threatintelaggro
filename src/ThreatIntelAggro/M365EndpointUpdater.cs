using System.Text.Json;

namespace ThreatIntelAggro;

public static class IocExclusionSettings
{
    public static string Get(AppDatabase database, string key, string fallback = "") =>
        database.Query("SELECT value FROM app_settings WHERE key=?", key).FirstOrDefault()?["value"] ?? fallback;

    public static void Set(AppDatabase database, string key, string value) =>
        database.Execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value);
}

public sealed class M365EndpointUpdater(AppDatabase database, IHttpClientFactory clients, ILogger<M365EndpointUpdater> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            await RefreshWhenDueAsync(stoppingToken);
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task RefreshWhenDueAsync(CancellationToken cancellationToken)
    {
        var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var lastRefresh = IocExclusionSettings.Get(database, "m365_endpoints_refreshed_utc");
        if (DateTimeOffset.TryParse(lastRefresh, out var refreshed) && refreshed.UtcDateTime.ToString("yyyy-MM-dd") == today) return;

        var requestDate = IocExclusionSettings.Get(database, "m365_request_date");
        var requestId = IocExclusionSettings.Get(database, "m365_request_id");
        if (requestDate != today || !Guid.TryParse(requestId, out _))
        {
            requestDate = today;
            requestId = Guid.NewGuid().ToString("D");
            IocExclusionSettings.Set(database, "m365_request_date", requestDate);
            IocExclusionSettings.Set(database, "m365_request_id", requestId);
        }

        try
        {
            var client = clients.CreateClient(nameof(M365EndpointUpdater));
            using var response = await client.GetAsync($"https://endpoints.office.com/endpoints/worldwide?clientrequestid={Uri.EscapeDataString(requestId)}", cancellationToken);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(json);
            var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (document.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Microsoft 365 endpoint response was not a JSON array.");
            foreach (var endpoint in document.RootElement.EnumerateArray())
            {
                Add(endpoint, "urls", urls);
                Add(endpoint, "ips", ips);
            }
            IocExclusionSettings.Set(database, "m365_endpoints_json", JsonSerializer.Serialize(new { urls = urls.OrderBy(x => x), ips = ips.OrderBy(x => x) }));
            IocExclusionSettings.Set(database, "m365_endpoints_refreshed_utc", DateTimeOffset.UtcNow.ToString("O"));
            IocExclusionSettings.Set(database, "m365_endpoints_error", "");
            log.LogInformation("Refreshed Microsoft 365 endpoint exclusions: {UrlCount} URL patterns and {IpCount} address ranges", urls.Count, ips.Count);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            var message = exception.Message.Length > 300 ? exception.Message[..300] : exception.Message;
            IocExclusionSettings.Set(database, "m365_endpoints_error", message);
            log.LogWarning("Microsoft 365 endpoint refresh failed: {Message}", message);
        }
    }

    private static void Add(JsonElement endpoint, string property, HashSet<string> values)
    {
        if (endpoint.TryGetProperty(property, out var list) && list.ValueKind == JsonValueKind.Array)
            foreach (var item in list.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString())) values.Add(item.GetString()!.Trim());
    }
}
