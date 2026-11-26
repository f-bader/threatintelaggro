namespace ThreatIntelAggro;

public static class InboxCoverageSettings
{
    public const string DefaultViewKey = "inbox_default_coverage_view";
    public const string DefaultView = "topics";

    public static bool IsValidView(string? value) => value is "articles" or "duplicates" or "topics";

    public static string ReadDefaultView(AppDatabase database)
    {
        var configured = IocExclusionSettings.Get(database, DefaultViewKey, DefaultView);
        return IsValidView(configured) ? configured : DefaultView;
    }
}
