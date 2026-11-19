using System.Threading.Channels;

namespace ThreatIntelAggro;

public sealed record ManualJobStatus(string State, string Message);

public sealed class ManualJobs(IServiceScopeFactory scopes, ILogger<ManualJobs> logger) : BackgroundService
{
    private readonly record struct Job(string Key, long? FeedId);
    private readonly Channel<Job> _queue = Channel.CreateBounded<Job>(24);
    private readonly Dictionary<string, ManualJobStatus> _statuses = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public static string FeedKey(long id) => $"feed-{id}";
    public const string BriefingKey = "briefing";

    public ManualJobStatus EnqueueFeed(long id) => Enqueue(new Job(FeedKey(id), id));
    public ManualJobStatus EnqueueBriefing() => Enqueue(new Job(BriefingKey, null));

    public ManualJobStatus? Status(string key)
    {
        lock (_gate) return _statuses.GetValueOrDefault(key);
    }

    private ManualJobStatus Enqueue(Job job)
    {
        lock (_gate)
        {
            if (_statuses.TryGetValue(job.Key, out var existing) && existing.State is "queued" or "running")
                return existing;
            if (_statuses.Count >= 100)
            {
                var completed = _statuses.FirstOrDefault(pair => pair.Value.State is "complete" or "failed");
                if (completed.Key is not null) _statuses.Remove(completed.Key);
            }

            if (!_queue.Writer.TryWrite(job)) return new("failed", "The job queue is full. Try again shortly.");
            return _statuses[job.Key] = new("queued", job.FeedId is null ? "Briefing generation queued." : "Feed refresh queued.");
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            lock (_gate) _statuses[job.Key] = new("running", job.FeedId is null ? "Generating briefing…" : "Refreshing feed…");
            ManualJobStatus result;
            try
            {
                using var scope = scopes.CreateScope();
                if (job.FeedId is long id)
                {
                    var count = await scope.ServiceProvider.GetRequiredService<FeedReader>().RefreshAsync(id, stoppingToken);
                    result = new("complete", $"Refresh complete. {count} new article(s) found.");
                }
                else
                {
                    var count = await scope.ServiceProvider.GetRequiredService<BriefingService>().GenerateAsync(DateTimeOffset.UtcNow, stoppingToken);
                    result = new("complete", count == 0
                        ? "No applicable analyzed articles were found in the last 24 hours."
                        : $"Briefing generated from {count} applicable article(s).");
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception error)
            {
                logger.LogWarning(error, "Manual job {JobKey} failed", job.Key);
                result = new("failed", job.FeedId is null
                    ? "Briefing generation failed. Check the server logs."
                    : "Feed refresh failed. Check the source status.");
            }
            lock (_gate) _statuses[job.Key] = result;
        }
    }
}
