using System.Runtime.InteropServices;
using System.Text;

namespace ThreatIntelAggro;

public sealed class AppDatabase : IDisposable
{
    private readonly string _path;
    private readonly object _gate = new();
    private long _changeVersion;
    public long ChangeVersion => Interlocked.Read(ref _changeVersion);

    public AppDatabase(IWebHostEnvironment environment, string? dataDirectory = null)
    {
        var configured = dataDirectory ?? Environment.GetEnvironmentVariable("AGGRO_DATA_DIR");
        var directory = configured ?? Path.Combine(environment.ContentRootPath, "App_Data");
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "aggro.db");
    }

    public void Initialize()
    {
        lock (_gate)
        {
            Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
            Exec("""
                CREATE TABLE IF NOT EXISTS feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, url TEXT NOT NULL UNIQUE,
                    interval_hours INTEGER NOT NULL DEFAULT 6, enabled INTEGER NOT NULL DEFAULT 1, ioc_auto_approve INTEGER NOT NULL DEFAULT 0,
                    source_type TEXT NOT NULL DEFAULT 'rss',
                    last_checked_utc TEXT, last_error TEXT, created_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, feed_id INTEGER REFERENCES feeds(id) ON DELETE SET NULL,
                    feed_title TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
                    published_utc TEXT, first_seen_utc TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0,
                    ai_status TEXT NOT NULL DEFAULT 'pending', ai_error TEXT,
                    content_text TEXT NOT NULL DEFAULT '', analysis_json TEXT, analyzed_utc TEXT, evidence_verified INTEGER NOT NULL DEFAULT 0,
                    source_ledger_json TEXT NOT NULL DEFAULT '[]',
                    category TEXT NOT NULL DEFAULT 'Existing Research', category_manual INTEGER NOT NULL DEFAULT 0,
                    screenshot_data_url TEXT, screenshot_metadata_json TEXT,
                    UNIQUE(feed_title, url)
                );
                CREATE INDEX IF NOT EXISTS ix_articles_published ON articles(published_utc DESC);
                CREATE TABLE IF NOT EXISTS source_snapshots (
                    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                    source_id TEXT NOT NULL, content TEXT NOT NULL,
                    PRIMARY KEY(article_id,source_id)
                );
                CREATE TABLE IF NOT EXISTS analysis_responses (
                    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                    stage_key TEXT NOT NULL, response_id TEXT, status TEXT NOT NULL DEFAULT 'submitting',
                    result_text TEXT, error TEXT, search_citations_json TEXT NOT NULL DEFAULT '[]', updated_utc TEXT NOT NULL,
                    requested_model TEXT NOT NULL DEFAULT '', actual_model TEXT, reasoning_effort TEXT, config_revision INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(article_id,stage_key)
                );
                CREATE TABLE IF NOT EXISTS analysis_diagnostics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
                    briefing_window_start_utc TEXT, briefing_window_end_utc TEXT,
                    stage_key TEXT NOT NULL, error TEXT NOT NULL, raw_output TEXT,
                    created_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_analysis_diagnostics_created ON analysis_diagnostics(created_utc DESC);
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                    local_key TEXT NOT NULL, alert_title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'medium',
                    rationale TEXT NOT NULL DEFAULT '', kql TEXT NOT NULL, yaml TEXT NOT NULL DEFAULT '', playbook_json TEXT NOT NULL DEFAULT '{}',
                    mitre_json TEXT NOT NULL DEFAULT '[]', telemetry_json TEXT NOT NULL DEFAULT '{}', references_json TEXT NOT NULL DEFAULT '[]', behaviors_json TEXT NOT NULL DEFAULT '[]', source_ids_json TEXT NOT NULL DEFAULT '[]', xdr_tactic TEXT NOT NULL DEFAULT '', xdr_techniques_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'new', archived INTEGER NOT NULL DEFAULT 0, validation_state TEXT NOT NULL DEFAULT 'pending',
                    validation_json TEXT NOT NULL DEFAULT '{}', guid TEXT NOT NULL, created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL,
                    UNIQUE(article_id,local_key)
                );
                CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS briefing_follows (id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL CHECK(kind IN ('vendor','industry','product')),name TEXT NOT NULL,is_enabled INTEGER NOT NULL DEFAULT 1,is_custom INTEGER NOT NULL DEFAULT 0,UNIQUE(kind,name COLLATE NOCASE));
                CREATE TABLE IF NOT EXISTS briefings (id INTEGER PRIMARY KEY AUTOINCREMENT,window_start_utc TEXT NOT NULL,window_end_utc TEXT NOT NULL,created_utc TEXT NOT NULL,title TEXT NOT NULL,executive_summary TEXT NOT NULL,detection_summary TEXT NOT NULL,ioc_summary TEXT NOT NULL,article_ids_json TEXT NOT NULL,article_snapshot_json TEXT NOT NULL,markdown TEXT NOT NULL,detections_snapshot_json TEXT,iocs_snapshot_json TEXT,UNIQUE(window_start_utc,window_end_utc));
                CREATE INDEX IF NOT EXISTS ix_briefings_created ON briefings(created_utc DESC);
                CREATE TABLE IF NOT EXISTS article_ai_config (article_id INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,config_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS ioc_exclusions (id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT NOT NULL UNIQUE,created_utc TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS ioc_dismissals (article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,ioc_type TEXT NOT NULL,ioc_value TEXT NOT NULL,dismissed_utc TEXT NOT NULL,PRIMARY KEY(article_id,ioc_type,ioc_value));
                CREATE TABLE IF NOT EXISTS ioc_role_overrides (
                    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                    ioc_type TEXT NOT NULL,ioc_value TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('malicious','suspicious')),
                    updated_utc TEXT NOT NULL,PRIMARY KEY(article_id,ioc_type,ioc_value)
                );
                CREATE TABLE IF NOT EXISTS ioc_approvals (article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,ioc_type TEXT NOT NULL,ioc_value TEXT NOT NULL,approved_utc TEXT NOT NULL,PRIMARY KEY(article_id,ioc_type,ioc_value));
                CREATE INDEX IF NOT EXISTS ix_detections_created ON detections(created_utc DESC);
                """);
            // Upgrade databases created by earlier local builds.
            foreach (var migration in new[] {
                "ALTER TABLE feeds ADD COLUMN ioc_auto_approve INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE feeds ADD COLUMN source_type TEXT NOT NULL DEFAULT 'rss'",
                "ALTER TABLE articles ADD COLUMN ai_status TEXT NOT NULL DEFAULT 'pending'",
                "ALTER TABLE articles ADD COLUMN ai_error TEXT",
                "ALTER TABLE articles ADD COLUMN content_text TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE articles ADD COLUMN analysis_json TEXT",
                "ALTER TABLE articles ADD COLUMN evidence_verified INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE articles ADD COLUMN analyzed_utc TEXT",
                "ALTER TABLE articles ADD COLUMN source_ledger_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE articles ADD COLUMN category TEXT NOT NULL DEFAULT 'Existing Research'",
                "ALTER TABLE articles ADD COLUMN category_manual INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE articles ADD COLUMN screenshot_data_url TEXT",
                "ALTER TABLE articles ADD COLUMN screenshot_metadata_json TEXT"
            }) { try { Exec(migration); } catch (InvalidOperationException e) when (e.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase)) { } }
            foreach (var migration in new[] {
                "ALTER TABLE briefings ADD COLUMN detections_snapshot_json TEXT",
                "ALTER TABLE briefings ADD COLUMN iocs_snapshot_json TEXT"
            }) { try { Exec(migration); } catch (InvalidOperationException e) when (e.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase)) { } }
            var followDefinition = Query("SELECT sql FROM sqlite_master WHERE type='table' AND name='briefing_follows'").FirstOrDefault()?.GetValueOrDefault("sql") ?? "";
            if (!followDefinition.Contains("'product'", StringComparison.OrdinalIgnoreCase))
            {
                Exec("BEGIN IMMEDIATE; CREATE TABLE briefing_follows_new (id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL CHECK(kind IN ('vendor','industry','product')),name TEXT NOT NULL,is_enabled INTEGER NOT NULL DEFAULT 1,is_custom INTEGER NOT NULL DEFAULT 0,UNIQUE(kind,name COLLATE NOCASE)); INSERT INTO briefing_follows_new(id,kind,name,is_enabled,is_custom) SELECT id,kind,name,is_enabled,is_custom FROM briefing_follows; DROP TABLE briefing_follows; ALTER TABLE briefing_follows_new RENAME TO briefing_follows; COMMIT;");
            }
            foreach (var migration in new[] { "ALTER TABLE detections ADD COLUMN xdr_tactic TEXT NOT NULL DEFAULT ''", "ALTER TABLE detections ADD COLUMN xdr_techniques_json TEXT NOT NULL DEFAULT '[]'", "ALTER TABLE detections ADD COLUMN behaviors_json TEXT NOT NULL DEFAULT '[]'", "ALTER TABLE detections ADD COLUMN source_ids_json TEXT NOT NULL DEFAULT '[]'" })
            { try { Exec(migration); } catch (InvalidOperationException e) when (e.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase)) { } }
            try { Exec("ALTER TABLE detections ADD COLUMN guid TEXT NOT NULL DEFAULT ''"); } catch (InvalidOperationException e) when (e.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase)) { }
            foreach (var migration in new[] {
                "ALTER TABLE analysis_responses ADD COLUMN requested_model TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE analysis_responses ADD COLUMN actual_model TEXT",
                "ALTER TABLE analysis_responses ADD COLUMN reasoning_effort TEXT",
                "ALTER TABLE analysis_responses ADD COLUMN config_revision INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE analysis_responses ADD COLUMN search_citations_json TEXT NOT NULL DEFAULT '[]'"
            }) { try { Exec(migration); } catch (InvalidOperationException e) when (e.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase)) { } }
            Exec("UPDATE detections SET guid=lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-a' || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))) WHERE guid=''");
            Exec("UPDATE articles SET ai_status='pending',ai_error=NULL WHERE ai_status='analyzing'");
        }
    }

    public void SeedUnit42()
    {
        lock (_gate)
        {
            Execute("INSERT OR IGNORE INTO feeds(title,url,interval_hours,enabled,created_utc) VALUES(?,?,?,?,?)",
                "Unit 42", "https://unit42.paloaltonetworks.com/feed/", 6, 1, DateTimeOffset.UtcNow.ToString("O"));
        }
    }

    public List<Dictionary<string, string?>> Query(string sql, params object?[] args)
    {
        lock (_gate)
        {
            var rows = new List<Dictionary<string, string?>>();
            WithStatement(sql, args, statement =>
            {
                var columns = Native.sqlite3_column_count(statement);
                int status;
                while ((status = Native.sqlite3_step(statement)) == 100)
                {
                    var row = new Dictionary<string, string?>();
                    for (var index = 0; index < columns; index++)
                    {
                        var name = Marshal.PtrToStringUTF8(Native.sqlite3_column_name(statement, index)) ?? index.ToString();
                        var value = Native.sqlite3_column_text(statement, index);
                        row[name] = value == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(value);
                    }
                    rows.Add(row);
                }
                if (status != 101) throw Error(status);
            });
            return rows;
        }
    }

    public int Execute(string sql, params object?[] args)
    {
        lock (_gate)
        {
            var changed = 0;
            WithStatement(sql, args, statement =>
            {
                var status = Native.sqlite3_step(statement);
                if (status != 101) throw Error(status);
                changed = Native.sqlite3_changes(_handle);
                if (changed != 0) Interlocked.Increment(ref _changeVersion);
            });
            return changed;
        }
    }

    public void Transaction(Action action)
    {
        lock (_gate)
        {
            Exec("BEGIN IMMEDIATE");
            try { action(); Exec("COMMIT"); }
            catch { Exec("ROLLBACK"); throw; }
        }
    }

    public void BackupTo(string destination)
    {
        lock (_gate)
        {
            EnsureOpen();
            using (new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
            IntPtr target = IntPtr.Zero;
            IntPtr backup = IntPtr.Zero;
            try
            {
                var status = Native.sqlite3_open(destination, out target);
                if (status != 0) throw new InvalidOperationException($"Cannot open backup database: {status}");
                backup = Native.sqlite3_backup_init(target, "main", _handle, "main");
                if (backup == IntPtr.Zero) throw new InvalidOperationException($"Cannot initialize SQLite backup: {Marshal.PtrToStringUTF8(Native.sqlite3_errmsg(target))}");
                status = Native.sqlite3_backup_step(backup, -1);
                if (status != 101) throw new InvalidOperationException($"SQLite backup failed: {status}");
                status = Native.sqlite3_backup_finish(backup);
                backup = IntPtr.Zero;
                if (status != 0) throw new InvalidOperationException($"SQLite backup failed: {status}");
                status = Native.sqlite3_exec(target, "PRAGMA journal_mode=DELETE", IntPtr.Zero, IntPtr.Zero, out var error);
                if (status != 0)
                {
                    var message = error == IntPtr.Zero ? "Cannot finalize backup journal" : Marshal.PtrToStringUTF8(error);
                    if (error != IntPtr.Zero) Native.sqlite3_free(error);
                    throw new InvalidOperationException(message);
                }
            }
            catch
            {
                if (backup != IntPtr.Zero) Native.sqlite3_backup_finish(backup);
                if (target != IntPtr.Zero) { Native.sqlite3_close(target); target = IntPtr.Zero; }
                File.Delete(destination);
                throw;
            }
            finally { if (target != IntPtr.Zero) Native.sqlite3_close(target); }
        }
    }

    public static void VerifyBackup(string path)
    {
        IntPtr db = IntPtr.Zero, statement = IntPtr.Zero;
        try
        {
            if (Native.sqlite3_open_v2(path, out db, 1, IntPtr.Zero) != 0) throw new InvalidOperationException("Cannot open backup database.");
            var status = Native.sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, out statement, IntPtr.Zero);
            if (status != 0) throw new InvalidOperationException($"Backup database integrity check could not start: {status} {Marshal.PtrToStringUTF8(Native.sqlite3_errmsg(db))}");
            status = Native.sqlite3_step(statement);
            if (status != 100) throw new InvalidOperationException($"Backup database integrity check failed: {status} {Marshal.PtrToStringUTF8(Native.sqlite3_errmsg(db))}");
            var result = Marshal.PtrToStringUTF8(Native.sqlite3_column_text(statement, 0));
            if (result != "ok" || Native.sqlite3_step(statement) != 101) throw new InvalidOperationException($"Backup database integrity check failed: {result}");
        }
        finally { if (statement != IntPtr.Zero) Native.sqlite3_finalize(statement); if (db != IntPtr.Zero) Native.sqlite3_close(db); }
    }

    public int ScalarInt(string sql, params object?[] args)
    {
        var result = Query(sql, args).FirstOrDefault()?.Values.FirstOrDefault();
        return int.TryParse(result, out var value) ? value : 0;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_handle == IntPtr.Zero) return;
            var status = Native.sqlite3_close(_handle);
            if (status != 0) throw Error(status);
            _handle = IntPtr.Zero;
        }
    }

    private IntPtr _handle;
    private void EnsureOpen()
    {
        if (_handle != IntPtr.Zero) return;
        var status = Native.sqlite3_open(_path, out _handle);
        if (status != 0) throw Error(status);
    }

    private void Exec(string sql)
    {
        EnsureOpen();
        var status = Native.sqlite3_exec(_handle, sql, IntPtr.Zero, IntPtr.Zero, out var error);
        if (status != 0)
        {
            var message = error == IntPtr.Zero ? "SQLite operation failed" : Marshal.PtrToStringUTF8(error);
            if (error != IntPtr.Zero) Native.sqlite3_free(error);
            throw new InvalidOperationException(message);
        }
    }

    private void WithStatement(string sql, object?[] args, Action<IntPtr> action)
    {
        EnsureOpen();
        var status = Native.sqlite3_prepare_v2(_handle, sql, -1, out var statement, IntPtr.Zero);
        if (status != 0) throw Error(status);
        try
        {
            for (var i = 0; i < args.Length; i++)
            {
                var index = i + 1;
                var value = args[i];
                status = value switch
                {
                    null => Native.sqlite3_bind_null(statement, index),
                    int integer => Native.sqlite3_bind_int64(statement, index, integer),
                    long integer => Native.sqlite3_bind_int64(statement, index, integer),
                    bool boolean => Native.sqlite3_bind_int64(statement, index, boolean ? 1 : 0),
                    _ => Native.sqlite3_bind_text(statement, index, Encoding.UTF8.GetBytes(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) + "\0"), -1, new IntPtr(-1))
                };
                if (status != 0) throw Error(status);
            }
            action(statement);
        }
        finally { Native.sqlite3_finalize(statement); }
    }

    private Exception Error(int status) => new InvalidOperationException($"SQLite error {status}: {Marshal.PtrToStringUTF8(Native.sqlite3_errmsg(_handle))}");

    private static class Native
    {
        private const string Library = "sqlite3";
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_open([MarshalAs(UnmanagedType.LPUTF8Str)] string filename, out IntPtr db);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_close(IntPtr db);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_open_v2([MarshalAs(UnmanagedType.LPUTF8Str)] string filename, out IntPtr db, int flags, IntPtr vfs);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr sqlite3_errmsg(IntPtr db);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_exec(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, IntPtr callback, IntPtr arg, out IntPtr error);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern void sqlite3_free(IntPtr pointer);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_prepare_v2(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, int bytes, out IntPtr statement, IntPtr tail);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_step(IntPtr statement);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_finalize(IntPtr statement);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_bind_null(IntPtr statement, int index);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_bind_int64(IntPtr statement, int index, long value);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_bind_text(IntPtr statement, int index, byte[] value, int bytes, IntPtr destructor);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_column_count(IntPtr statement);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr sqlite3_column_name(IntPtr statement, int index);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr sqlite3_column_text(IntPtr statement, int index);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr sqlite3_backup_init(IntPtr destination, [MarshalAs(UnmanagedType.LPUTF8Str)] string destinationName, IntPtr source, [MarshalAs(UnmanagedType.LPUTF8Str)] string sourceName);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_backup_step(IntPtr backup, int pages);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_backup_finish(IntPtr backup);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int sqlite3_changes(IntPtr db);
    }
}
