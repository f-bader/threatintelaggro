namespace ThreatIntelAggro;

public static class AnalysisDiagnostics
{
    private const int MaxRawOutputLength = 100_000;
    private const int MaxErrorLength = 2_000;
    private const int RetainedFailureCount = 500;

    public static void RecordArticle(AppDatabase database, long articleId, string stage, string error, string? rawOutput)
    {
        Record(database, articleId, null, null, stage, error, rawOutput);
    }

    public static void RecordBriefing(AppDatabase database, DateTimeOffset start, DateTimeOffset end, string error, string? rawOutput)
    {
        Record(database, null, start.ToUniversalTime().ToString("O"), end.ToUniversalTime().ToString("O"), "briefing-generation", error, rawOutput);
    }

    private static void Record(AppDatabase database, long? articleId, string? windowStart, string? windowEnd, string stage, string error, string? rawOutput)
    {
        var created = DateTimeOffset.UtcNow.ToString("O");
        var safeError = string.IsNullOrWhiteSpace(error) ? "The stage failed without an error message." : error.Trim();
        if (safeError.Length > MaxErrorLength) safeError = safeError[..MaxErrorLength];
        if (rawOutput?.Length > MaxRawOutputLength) rawOutput = rawOutput[..MaxRawOutputLength] + "\n[truncated]";
        database.Execute("INSERT INTO analysis_diagnostics(article_id,briefing_window_start_utc,briefing_window_end_utc,stage_key,error,raw_output,created_utc) VALUES(?,?,?,?,?,?,?)",
            articleId, windowStart, windowEnd, stage, safeError, rawOutput, created);
        database.Execute("DELETE FROM analysis_diagnostics WHERE id NOT IN (SELECT id FROM analysis_diagnostics ORDER BY id DESC LIMIT ?)", RetainedFailureCount);
    }
}
