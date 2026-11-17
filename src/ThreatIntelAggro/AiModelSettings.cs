using System.Text.Json;
using System.Text.RegularExpressions;

namespace ThreatIntelAggro;

public sealed record AiModelSettings(
    string Model = "",
    string Effort = "",
    string ResearchModel = "",
    string ResearchEffort = "",
    string ArticleModel = "",
    string ArticleEffort = "",
    string DetectionModel = "",
    string DetectionEffort = "",
    string RepairModel = "",
    string RepairEffort = "",
    long Revision = 0)
{
    public bool IsConfigured => !string.IsNullOrWhiteSpace(Model) && IsValidEffort(Effort);

    public (string Model, string? Effort) ForStage(string stage) => stage switch
    {
        "research" => (Choose(ResearchModel), ChooseEffort(ResearchEffort)),
        "article-analysis" => (Choose(ArticleModel), ChooseEffort(ArticleEffort)),
        "detection-generation" => (Choose(DetectionModel), ChooseEffort(DetectionEffort)),
        _ when stage.StartsWith("kql-repair-", StringComparison.Ordinal) || stage.EndsWith("-evidence-repair", StringComparison.Ordinal) || stage.EndsWith("-validation-repair", StringComparison.Ordinal) => (Choose(RepairModel), ChooseEffort(RepairEffort)),
        _ => (Model, Effort.Length == 0 ? null : Effort)
    };

    private string Choose(string value) => string.IsNullOrWhiteSpace(value) ? Model : value;
    private string? ChooseEffort(string value) => string.IsNullOrWhiteSpace(value) ? Effort.Length == 0 ? null : Effort : value;

    public static bool IsValidEffort(string? effort) => effort is "" or "none" or "low" or "medium" or "high" or "xhigh" or "max";
    public static bool IsValidModel(string? model) => !string.IsNullOrWhiteSpace(model) && model.Length <= 200 && Regex.IsMatch(model, "^[A-Za-z0-9][A-Za-z0-9._:/-]*$");
}

public sealed class AiModelSettingsService(AppDatabase database, IConfiguration configuration)
{
    private const string Key = "ai_model_settings";
    private readonly object _gate = new();

    public AiModelSettings Read()
    {
        lock (_gate)
        {
            var saved = IocExclusionSettings.Get(database, Key);
            if (!string.IsNullOrWhiteSpace(saved))
            {
                try { return JsonSerializer.Deserialize<AiModelSettings>(saved) ?? new(); }
                catch (JsonException) { return new(); }
            }

            // Import the old effective defaults only for a database that already contains application data.
            if (database.ScalarInt("SELECT COUNT(*) FROM articles") == 0 && IocExclusionSettings.Get(database, "ai_settings_legacy_pending") != "true")
                return new();

            var legacy = new AiModelSettings(
                Model: configuration["OpenAI:Model"] ?? "gpt-6-luna",
                Effort: configuration["OpenAI:ReasoningEffort"] ?? "high",
                ResearchEffort: configuration["OpenAI:ResearchEffort"] ?? "low",
                ArticleEffort: configuration["OpenAI:AnalysisEffort"] ?? "high",
                DetectionEffort: configuration["OpenAI:AnalysisEffort"] ?? "high",
                RepairEffort: configuration["OpenAI:RepairEffort"] ?? "low",
                Revision: 1);
            SaveCore(legacy);
            IocExclusionSettings.Set(database, "ai_settings_legacy_pending", "false");
            return legacy;
        }
    }

    public AiModelSettings Save(AiModelSettings settings)
    {
        if (!AiModelSettings.IsValidModel(settings.Model)) throw new ArgumentException("Enter a valid model or deployment ID (letters, numbers, dot, underscore, colon, slash, or hyphen).", nameof(settings));
        foreach (var (name, value) in new[]
        {
            ("default", settings.Effort), ("research", settings.ResearchEffort), ("article analysis", settings.ArticleEffort),
            ("detection generation", settings.DetectionEffort), ("KQL repair", settings.RepairEffort)
        })
            if (!AiModelSettings.IsValidEffort(value)) throw new ArgumentException($"Choose a supported effort for {name}.", nameof(settings));
        foreach (var (name, value) in new[]
        {
            ("research", settings.ResearchModel), ("article analysis", settings.ArticleModel),
            ("detection generation", settings.DetectionModel), ("KQL repair", settings.RepairModel)
        })
            if (value.Length > 0 && !AiModelSettings.IsValidModel(value)) throw new ArgumentException($"Enter a valid model ID for {name}.", nameof(settings));

        lock (_gate)
        {
            var revision = ReadRevision() + 1;
            return SaveCore(settings with { Revision = revision });
        }
    }

    public static object Snapshot(AiModelSettings settings) => new
    {
        settings.Model, settings.Effort, settings.ResearchModel, settings.ResearchEffort,
        settings.ArticleModel, settings.ArticleEffort, settings.DetectionModel, settings.DetectionEffort,
        settings.RepairModel, settings.RepairEffort, settings.Revision
    };

    public static AiModelSettings FromSnapshot(string json) => JsonSerializer.Deserialize<AiModelSettings>(json) ?? new();

    private long ReadRevision()
    {
        var current = IocExclusionSettings.Get(database, Key);
        if (current is null) return 0;
        try { return JsonSerializer.Deserialize<AiModelSettings>(current)?.Revision ?? 0; }
        catch (JsonException) { return 0; }
    }

    private AiModelSettings SaveCore(AiModelSettings settings)
    {
        database.Execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", Key, JsonSerializer.Serialize(settings));
        return settings;
    }
}
