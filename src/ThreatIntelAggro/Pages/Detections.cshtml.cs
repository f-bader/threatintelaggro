using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class DetectionsModel(AppDatabase database) : PageModel
{
    public static System.Text.Json.Nodes.JsonArray Behaviors(string? json)
    {
        try { return System.Text.Json.Nodes.JsonNode.Parse(json ?? "[]") as System.Text.Json.Nodes.JsonArray ?? []; }
        catch (System.Text.Json.JsonException) { return []; }
    }
    public IReadOnlyList<Dictionary<string, string?>> Items { get; private set; } = [];
    [BindProperty(SupportsGet = true)] public string State { get; set; } = "active";
    [BindProperty(SupportsGet = true)] public long? ArticleId { get; set; }
    public string? FilterArticleTitle { get; private set; }
    public void OnGet() => Load();
    public IActionResult OnPostUpdate(long id, string status, string? returnState)
    {
        if (!new[] { "new", "reviewing", "accepted", "rejected", "implemented" }.Contains(status)) status = "new";
        database.Execute("UPDATE detections SET status=?,updated_utc=? WHERE id=?", status, DateTimeOffset.UtcNow.ToString("O"), id);
        return RedirectToPage(new { state = returnState ?? "active", articleId = ArticleId });
    }
    public IActionResult OnPostArchive(long id, string? returnState)
    {
        database.Execute("UPDATE detections SET archived=1,updated_utc=? WHERE id=?", DateTimeOffset.UtcNow.ToString("O"), id);
        return RedirectToPage(new { state = returnState ?? "active", articleId = ArticleId });
    }
    public IActionResult OnPostUnarchive(long id, string? returnState)
    {
        database.Execute("UPDATE detections SET archived=0,updated_utc=? WHERE id=?", DateTimeOffset.UtcNow.ToString("O"), id);
        return RedirectToPage(new { state = returnState ?? "archived", articleId = ArticleId });
    }
    public IActionResult OnPostDelete(long id)
    {
        database.Execute("DELETE FROM detections WHERE id=?", id);
        return RedirectToPage(new { state = State, articleId = ArticleId });
    }
    public IActionResult OnGetYaml(long id)
    {
        var detection = database.Query("SELECT * FROM detections WHERE id=?", id).FirstOrDefault();
        if (detection is null) return NotFound();
        try
        {
            var yaml = AnalysisService.ExportYaml(detection);
            return File(System.Text.Encoding.UTF8.GetBytes(yaml), "application/yaml", $"threat-intel-aggro-{id}.yaml");
        }
        catch (InvalidOperationException ex) { return new ObjectResult(ex.Message) { StatusCode = StatusCodes.Status422UnprocessableEntity }; }
    }
    public IActionResult OnGetKql(long id)
    {
        var detection = database.Query("SELECT kql FROM detections WHERE id=?", id).FirstOrDefault();
        return detection is null ? NotFound() : File(System.Text.Encoding.UTF8.GetBytes(detection["kql"] ?? ""), "text/plain; charset=utf-8", $"threat-intel-aggro-{id}.kql");
    }
    public IActionResult OnGetJson(long id)
    {
        var detection = database.Query("SELECT d.*,a.title AS article_title,a.url AS article_url FROM detections d JOIN articles a ON a.id=d.article_id WHERE d.id=?", id).FirstOrDefault();
        if (detection is null) return NotFound();
        return File(System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(detection, new System.Text.Json.JsonSerializerOptions { WriteIndented = true })), "application/json", $"threat-intel-aggro-{id}.json");
    }
    private void Load()
    {
        var clauses = new List<string> { State == "archived" ? "d.archived=1" : "d.archived=0" };
        var args = new List<object?>();
        if (ArticleId is > 0) { clauses.Add("d.article_id=?"); args.Add(ArticleId.Value); FilterArticleTitle = database.Query("SELECT title FROM articles WHERE id=?", ArticleId.Value).FirstOrDefault()?.GetValueOrDefault("title"); }
        Items = database.Query($"SELECT d.*,a.title AS article_title,a.url AS article_url FROM detections d JOIN articles a ON a.id=d.article_id WHERE {string.Join(" AND ", clauses)} ORDER BY d.created_utc DESC", args.ToArray());
    }
}
