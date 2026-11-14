namespace ThreatIntelAggro;

public static class ArticleCategories
{
    public const string TimeCritical = "Time-Critical Threat";
    public const string NovelResearch = "Novel Research";
    public const string ActionableIocs = "Actionable IOCs";
    public const string ExistingResearch = "Existing Research";
    public const string Discard = "Discard";

    public static readonly string[] PriorityOrder = [TimeCritical, NovelResearch, ActionableIocs, ExistingResearch, Discard];

    public static bool IsValid(string? category) => PriorityOrder.Contains(category, StringComparer.OrdinalIgnoreCase);
    public static string Normalize(string? category) => PriorityOrder.FirstOrDefault(x => x.Equals(category, StringComparison.OrdinalIgnoreCase)) ?? ExistingResearch;
    public static int Priority(string? category) => Array.FindIndex(PriorityOrder, x => x.Equals(category, StringComparison.OrdinalIgnoreCase)) is var rank && rank >= 0 ? rank : PriorityOrder.Length;
}
