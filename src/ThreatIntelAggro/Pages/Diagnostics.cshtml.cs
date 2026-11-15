using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class DiagnosticsModel(AppDatabase database) : PageModel
{
    public IReadOnlyList<Dictionary<string, string?>> Failures { get; private set; } = [];

    public void OnGet() => Failures = database.Query("""
        SELECT d.id,d.stage_key,d.error,d.raw_output,d.created_utc,d.article_id,a.title AS article_title,
               d.briefing_window_start_utc,d.briefing_window_end_utc
        FROM analysis_diagnostics d LEFT JOIN articles a ON a.id=d.article_id
        ORDER BY d.id DESC LIMIT 100
        """);
}
