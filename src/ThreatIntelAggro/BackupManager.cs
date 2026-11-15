using System.Security.Cryptography;
using System.Text.Json;

namespace ThreatIntelAggro;

public sealed record BackupFile(string Path, string Sha256);
public sealed record BackupManifest(string Generator, int Version, DateTimeOffset CreatedUtc, BackupFile[] Files);

public sealed class BackupManager(AppDatabase database, IWebHostEnvironment environment)
{
    private const string Generator = "ThreatIntelAggro";
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    private readonly object _gate = new();
    private readonly string _dataDirectory = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR") ?? Path.Combine(environment.ContentRootPath, "App_Data");
    public string BackupDirectory => Path.Combine(_dataDirectory, "backups");

    public string CreateBackup()
    {
        lock (_gate)
        {
            Directory.CreateDirectory(BackupDirectory);
            var now = DateTimeOffset.UtcNow;
            var name = $"aggro-{now:yyyyMMddTHHmmssfffZ}-{Guid.NewGuid():N}";
            var temp = Path.Combine(BackupDirectory, ".staging-" + Guid.NewGuid().ToString("N"));
            var final = Path.Combine(BackupDirectory, name);
            try
            {
                CreatePrivateDirectory(temp);
                var keyDir = Path.Combine(temp, "keys");
                CreatePrivateDirectory(keyDir);
                var files = new List<BackupFile>();
                var sourceKeys = Path.Combine(_dataDirectory, "keys");
                if (Directory.Exists(sourceKeys))
                {
                    if ((File.GetAttributes(sourceKeys) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Key directories cannot be links.");
                    foreach (var file in Directory.EnumerateFiles(sourceKeys, "*.xml", SearchOption.TopDirectoryOnly))
                    {
                        if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Key file links cannot be backed up.");
                        var destination = Path.Combine(keyDir, Path.GetFileName(file));
                        File.Copy(file, destination, false);
                        MakePrivate(destination);
                        files.Add(new BackupFile("keys/" + Path.GetFileName(file), Hash(destination)));
                    }
                }
                var snapshot = Path.Combine(temp, "aggro.db");
                database.BackupTo(snapshot);
                MakePrivate(snapshot);
                AppDatabase.VerifyBackup(snapshot);
                files.Add(new BackupFile("aggro.db", Hash(snapshot)));
                var manifest = new BackupManifest(Generator, 1, now, files.ToArray());
                File.WriteAllText(Path.Combine(temp, "manifest.json"), JsonSerializer.Serialize(manifest, Options));
                MakePrivate(Path.Combine(temp, "manifest.json"));
                Directory.Move(temp, final);
                return final;
            }
            catch { if (Directory.Exists(temp)) Directory.Delete(temp, true); throw; }
        }
    }

    public static void RestoreToNewDirectory(string backupDirectory, string destination)
    {
        var source = Path.GetFullPath(backupDirectory);
        var target = Path.GetFullPath(destination);
        if (Directory.Exists(target) || File.Exists(target)) throw new InvalidOperationException("Restore destination must not already exist.");
        if ((File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0 || (Directory.Exists(Path.Combine(source, "keys")) && (File.GetAttributes(Path.Combine(source, "keys")) & FileAttributes.ReparsePoint) != 0)) throw new InvalidOperationException("Backup directories cannot be links.");
        var manifestPath = Path.Combine(source, "manifest.json");
        if ((File.GetAttributes(manifestPath) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Backup manifest cannot be a link.");
        var manifest = JsonSerializer.Deserialize<BackupManifest>(File.ReadAllText(manifestPath)) ?? throw new InvalidOperationException("Backup manifest is empty.");
        if (manifest.Generator != Generator || manifest.Version != 1 || manifest.Files is null || manifest.Files.Length is < 1 or > 1001 || manifest.Files.Any(x => x is null || x.Sha256 is null) || manifest.Files.Count(x => x.Path == "aggro.db") != 1) throw new InvalidOperationException("Invalid backup manifest.");
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in manifest.Files)
        {
            if (file.Path is null || !(file.Path == "aggro.db" || (file.Path.StartsWith("keys/", StringComparison.Ordinal) && file.Path.EndsWith(".xml", StringComparison.Ordinal) && Path.GetFileName(file.Path) == file.Path[5..])) || !paths.Add(file.Path)) throw new InvalidOperationException("Invalid path in backup manifest.");
            var sourceFile = Path.Combine(source, file.Path.Replace('/', Path.DirectorySeparatorChar));
            if ((File.GetAttributes(sourceFile) & FileAttributes.ReparsePoint) != 0 || !Hash(sourceFile).Equals(file.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Backup file integrity check failed.");
        }
        AppDatabase.VerifyBackup(Path.Combine(source, "aggro.db"));
        var parent = Path.GetDirectoryName(target) ?? throw new InvalidOperationException("Invalid restore destination.");
        var staging = Path.Combine(parent, ".aggro-restore-" + Guid.NewGuid().ToString("N"));
        try
        {
            CreatePrivateDirectory(staging);
            CreatePrivateDirectory(Path.Combine(staging, "keys"));
            foreach (var file in manifest.Files)
            {
                var relative = file.Path.Replace('/', Path.DirectorySeparatorChar);
                var output = Path.Combine(staging, relative);
                File.Copy(Path.Combine(source, relative), output, false);
                MakePrivate(output);
                if (!Hash(output).Equals(file.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Restored file integrity check failed.");
            }
            AppDatabase.VerifyBackup(Path.Combine(staging, "aggro.db"));
            Directory.Move(staging, target);
        }
        catch { if (Directory.Exists(staging)) Directory.Delete(staging, true); throw; }
    }

    public void Prune(DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!Directory.Exists(BackupDirectory)) return;
            var snapshots = new List<(string Path, DateTimeOffset Created)>();
            foreach (var dir in Directory.EnumerateDirectories(BackupDirectory, "aggro-*"))
            {
                try
                {
                    if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0 || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(dir), "^aggro-[0-9]{8}T[0-9]{9}Z-[0-9a-f]{32}$")) continue;
                    var manifest = JsonSerializer.Deserialize<BackupManifest>(File.ReadAllText(Path.Combine(dir, "manifest.json")));
                    if (manifest is { Generator: Generator, Version: 1 } && manifest.CreatedUtc <= now) snapshots.Add((dir, manifest.CreatedUtc));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
            }
            var ordered = snapshots.OrderByDescending(x => x.Created).ToArray();
            var daily = ordered.GroupBy(x => x.Created.UtcDateTime.Date).Select(x => x.First()).Take(7).ToArray();
            var keep = daily.Select(x => x.Path).ToHashSet(StringComparer.Ordinal);
            if (daily.Length == 7)
            {
                var cutoff = daily[^1].Created.UtcDateTime.Date;
                var weekly = ordered.Where(x => x.Created.UtcDateTime.Date < cutoff)
                    .GroupBy(x => (System.Globalization.ISOWeek.GetYear(x.Created.UtcDateTime), System.Globalization.ISOWeek.GetWeekOfYear(x.Created.UtcDateTime)))
                    .Select(x => x.First()).Take(4);
                foreach (var snapshot in weekly) keep.Add(snapshot.Path);
            }
            foreach (var snapshot in ordered.Where(x => !keep.Contains(x.Path))) Directory.Delete(snapshot.Path, true);
        }
    }

    public bool HasBackupToday(DateTimeOffset now)
    {
        if (!Directory.Exists(BackupDirectory)) return false;
        var prefix = $"aggro-{now.UtcDateTime:yyyyMMdd}";
        foreach (var path in Directory.EnumerateDirectories(BackupDirectory, prefix + "*"))
        {
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) continue;
                var manifest = JsonSerializer.Deserialize<BackupManifest>(File.ReadAllText(Path.Combine(path, "manifest.json")));
                if (manifest is { Generator: Generator, Version: 1 } && manifest.CreatedUtc.UtcDateTime.Date == now.UtcDateTime.Date && File.Exists(Path.Combine(path, "aggro.db"))) return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
        }
        return false;
    }

    private static string Hash(string file) { using var stream = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(stream)); }
    private static void CreatePrivateDirectory(string path) { Directory.CreateDirectory(path); if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
    private static void MakePrivate(string path) { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
}

public sealed class BackupWorker(BackupManager backups, ILogger<BackupWorker> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                if (!backups.HasBackupToday(now)) { var path = backups.CreateBackup(); backups.Prune(DateTimeOffset.UtcNow); log.LogInformation("Created database backup {BackupName}", Path.GetFileName(path)); }
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested) { log.LogError(ex, "Database backup failed"); }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
