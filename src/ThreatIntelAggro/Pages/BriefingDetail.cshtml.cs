using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class BriefingDetailModel(BriefingService briefings) : PageModel
{
    public Dictionary<string, string?>? Item { get; private set; }
    public System.Text.Json.JsonElement[] Articles { get; private set; } = [];
    public IActionResult OnGet(long id)
    {
        Item = briefings.Get(id); if (Item is null) return NotFound();
        try { Articles = System.Text.Json.JsonDocument.Parse(Item["article_snapshot_json"]!).RootElement.EnumerateArray().Select(x => x.Clone()).ToArray(); } catch { Articles = []; }
        return Page();
    }
}
