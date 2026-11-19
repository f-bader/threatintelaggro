namespace ThreatIntelAggro;

// Avoid reparsing every retained analysis on every rendered page. Database writes
// that affect indicators invalidate the count, while a short TTL also accounts for indicators expiring.
public sealed class IocCountCache(AppDatabase database)
{
    private readonly object _gate = new();
    private long _version = -1;
    private DateTimeOffset _expires = DateTimeOffset.MinValue;
    private int _count;

    public int GetCount()
    {
        lock (_gate)
        {
            var version = database.IocVersion;
            var now = DateTimeOffset.UtcNow;
            if (version == _version && now < _expires) return _count;
            var count = IocIndex.Read(database).Count;
            if (version == database.IocVersion)
            {
                _count = count;
                _version = version;
                _expires = now.AddSeconds(30);
            }
            return count;
        }
    }
}
