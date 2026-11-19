using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class IndexModel(BriefingService briefings, ManualJobs jobs) : PageModel
{
    public Dictionary<string, string?>? Latest { get; private set; }
    public IReadOnlyList<Dictionary<string, string?>> Archive { get; private set; } = [];
    public System.Text.Json.JsonElement[] Articles { get; private set; } = [];
    public BriefingDetection[] Detections { get; private set; } = [];
    public BriefingIoc[] Iocs { get; private set; } = [];
    [TempData] public string? Notice { get; set; }
    public void OnGet()
    {
        Latest = briefings.Latest; Archive = briefings.Archive;
        if (Latest is not null)
        {
            try { Articles = System.Text.Json.JsonDocument.Parse(Latest["article_snapshot_json"]!).RootElement.EnumerateArray().Select(x => x.Clone()).ToArray(); } catch { Articles = []; }
            Detections = briefings.GetDetections(Latest);
            Iocs = briefings.GetIocs(Latest);
        }
    }
    public ManualJobStatus? GenerationStatus => jobs.Status(ManualJobs.BriefingKey);

    public IActionResult OnPostGenerate()
    {
        var status = jobs.EnqueueBriefing();
        if (status.State == "failed") Notice = status.Message;
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
