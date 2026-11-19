using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ThreatIntelAggro.Pages;

public sealed class DetectionsModel(AppDatabase database) : PageModel
{
    public sealed record FamilyMember(string Id, string Title, string ArticleTitle, int Iteration);
    public static System.Text.Json.Nodes.JsonArray Behaviors(string? json)
    {
        try { return System.Text.Json.Nodes.JsonNode.Parse(json ?? "[]") as System.Text.Json.Nodes.JsonArray ?? []; }
        catch (System.Text.Json.JsonException) { return []; }
    }
    public IReadOnlyList<Dictionary<string, string?>> Items { get; private set; } = [];
    public IReadOnlyDictionary<long, IReadOnlyList<DetectionOverlap>> Overlaps { get; private set; } = new Dictionary<long, IReadOnlyList<DetectionOverlap>>();
    public IReadOnlyDictionary<string, IReadOnlyList<FamilyMember>> Families { get; private set; } = new Dictionary<string, IReadOnlyList<FamilyMember>>();
    public string? StatusMessage { get; private set; }
    [BindProperty(SupportsGet = true)] public string State { get; set; } = "active";
    [BindProperty(SupportsGet = true)] public long? ArticleId { get; set; }
    public string? FilterArticleTitle { get; private set; }
    public int ActiveCount => database.ScalarInt("SELECT COUNT(*) FROM detections WHERE archived=0");
    public void OnGet() => Load();
    public IActionResult OnPostUpdate(long id, string status, string? returnState)
    {
        if (!new[] { "new", "reviewing", "accepted", "rejected", "implemented" }.Contains(status)) status = "new";
        var changed = database.Execute("UPDATE detections SET status=?,updated_utc=? WHERE id=?", status, DateTimeOffset.UtcNow.ToString("O"), id);
        if (HttpContext is not null && Request.Headers["X-Review-Fragment"].ToString() == "detections")
            return changed > 0 ? new JsonResult(new { status }) : NotFound();
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
    public IActionResult OnPostGroupAsIterations(long id, long relatedId, string? returnState)
    {
        if (id <= 0 || relatedId <= 0 || id == relatedId)
        {
            TempData["DetectionGroupingMessage"] = "Choose two different detection drafts to group.";
            return RedirectToPage(new { state = returnState ?? "active", articleId = ArticleId });
        }

        var message = "These detections are now grouped as iterations.";
        database.Transaction(() =>
        {
            var pair = database.Query("SELECT id,family_id,iteration_number,archived,created_utc FROM detections WHERE id IN (?,?) ORDER BY created_utc,id", id, relatedId);
            if (pair.Count != 2 || pair.Any(x => x["archived"] != "0"))
            {
                message = "Both drafts must exist and be active before they can be grouped.";
                return;
            }
            var leftFamily = pair[0]["family_id"];
            var rightFamily = pair[1]["family_id"];
            if (!string.IsNullOrEmpty(leftFamily) && !string.IsNullOrEmpty(rightFamily) && leftFamily != rightFamily)
            {
                message = "These drafts already belong to different iteration groups. Ungroup one first.";
                return;
            }

            var familyId = leftFamily ?? rightFamily ?? Guid.NewGuid().ToString("N");
            var nextIteration = database.ScalarInt("SELECT COALESCE(MAX(iteration_number),0)+1 FROM detections WHERE family_id=?", familyId);
            foreach (var item in pair)
            {
                if (item["family_id"] == familyId) continue;
                var iteration = nextIteration++;
                database.Execute("UPDATE detections SET family_id=?,iteration_number=?,updated_utc=? WHERE id=? AND family_id IS NULL", familyId, iteration, DateTimeOffset.UtcNow.ToString("O"), item["id"]);
            }
        });
        TempData["DetectionGroupingMessage"] = message;
        if (message == "These detections are now grouped as iterations.") ArticleId = null;
        return RedirectToPage(new { state = returnState ?? "active", articleId = ArticleId });
    }
    public IActionResult OnPostUngroup(long id, string? returnState)
    {
        database.Transaction(() =>
        {
            var familyId = database.Query("SELECT family_id FROM detections WHERE id=?", id).FirstOrDefault()?.GetValueOrDefault("family_id");
            if (string.IsNullOrEmpty(familyId)) return;
            database.Execute("UPDATE detections SET family_id=NULL,iteration_number=0,updated_utc=? WHERE id=?", DateTimeOffset.UtcNow.ToString("O"), id);
            if (database.ScalarInt("SELECT COUNT(*) FROM detections WHERE family_id=?", familyId) <= 1)
                database.Execute("UPDATE detections SET family_id=NULL,iteration_number=0 WHERE family_id=?", familyId);
        });
        TempData["DetectionGroupingMessage"] = "Detection removed from its iteration group.";
        return RedirectToPage(new { state = returnState ?? "active", articleId = ArticleId });
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
        StatusMessage = TempData["DetectionGroupingMessage"] as string;
        var clauses = new List<string> { State == "archived" ? "d.archived=1" : "d.archived=0" };
        var args = new List<object?>();
        if (ArticleId is > 0) { clauses.Add("d.article_id=?"); args.Add(ArticleId.Value); FilterArticleTitle = database.Query("SELECT title FROM articles WHERE id=?", ArticleId.Value).FirstOrDefault()?.GetValueOrDefault("title"); }
        Items = database.Query($"SELECT d.*,a.title AS article_title,a.url AS article_url FROM detections d JOIN articles a ON a.id=d.article_id WHERE {string.Join(" AND ", clauses)} ORDER BY d.created_utc DESC", args.ToArray());
        var allVisible = ArticleId is not > 0 ? Items : database.Query($"SELECT d.*,a.title AS article_title,a.url AS article_url FROM detections d JOIN articles a ON a.id=d.article_id WHERE d.archived=? ORDER BY d.created_utc DESC", State == "archived" ? 1 : 0);
        Overlaps = State == "archived" ? new Dictionary<long, IReadOnlyList<DetectionOverlap>>() : DetectionOverlapMatcher.FindForQueue(Items, allVisible);
        Families = allVisible.Where(x => !string.IsNullOrEmpty(x["family_id"]))
            .GroupBy(x => x["family_id"]!, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<FamilyMember>)g.OrderBy(x => int.TryParse(x["iteration_number"], out var order) ? order : int.MaxValue)
                .Select(x => new FamilyMember(x["id"] ?? "", x["alert_title"] ?? "Detection", x["article_title"] ?? "", int.TryParse(x["iteration_number"], out var iteration) ? iteration : 0)).ToArray(), StringComparer.Ordinal);
    }
}
