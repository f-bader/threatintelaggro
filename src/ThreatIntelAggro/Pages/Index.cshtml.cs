using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class IndexModel(BriefingService briefings) : PageModel
{
    public Dictionary<string, string?>? Latest { get; private set; }
    public IReadOnlyList<Dictionary<string, string?>> Archive { get; private set; } = [];
    public System.Text.Json.JsonElement[] Articles { get; private set; } = [];
    [TempData] public string? Notice { get; set; }
    public void OnGet()
    {
        Latest = briefings.Latest; Archive = briefings.Archive;
        if (Latest is not null) try { Articles = System.Text.Json.JsonDocument.Parse(Latest["article_snapshot_json"]!).RootElement.EnumerateArray().Select(x => x.Clone()).ToArray(); } catch { Articles = []; }
    }
    public async Task<IActionResult> OnPostGenerateAsync(CancellationToken cancellationToken)
    {
        try { var count = await briefings.GenerateAsync(DateTimeOffset.UtcNow, cancellationToken); Notice = count == 0 ? "No applicable analyzed articles were found in the last 24 hours; no briefing was created." : $"Briefing generated from {count} applicable article(s)."; }
        catch (Exception ex) when (ex is not OperationCanceledException) { Notice = $"Briefing generation failed: {ex.Message}"; }
        return RedirectToPage();
    }
    public IActionResult OnGetMarkdown(long id) => Export(id, false);
    public IActionResult OnGetPdf(long id) => Export(id, true);
    private IActionResult Export(long id, bool pdf)
    {
        var row = briefings.Get(id);
        if (row is null) return NotFound();
        var title = RegexSafe(row["title"] ?? "briefing");
        return pdf ? File(BriefingExport.Pdf(row["markdown"] ?? ""), "application/pdf", $"{title}.pdf") : File(System.Text.Encoding.UTF8.GetBytes(row["markdown"] ?? ""), "text/markdown; charset=utf-8", $"{title}.md");
    }
    private static string RegexSafe(string value) => System.Text.RegularExpressions.Regex.Replace(value.ToLowerInvariant(), "[^a-z0-9-]+", "-").Trim('-');
}
