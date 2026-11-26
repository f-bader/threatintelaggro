using System.Globalization;
using System.Threading.RateLimiting;
using ThreatIntelAggro;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

const string IocRateLimit = "ioc-api";
const string RssRateLimit = "briefing-rss";

if (args.Length > 0 && args[0] == "--restore-backup")
{
    if (args.Length != 3) { Console.Error.WriteLine("Usage: --restore-backup <backup-directory> <new-destination-directory>"); Environment.ExitCode = 2; return; }
    try { BackupManager.RestoreToNewDirectory(args[1], args[2]); Console.WriteLine("Backup verified and restored to the new directory."); }
    catch (Exception ex) { Console.Error.WriteLine($"Restore failed: {ex.Message}"); Environment.ExitCode = 1; }
    return;
}

var builder = WebApplication.CreateBuilder(args);
if (builder.Environment.IsDevelopment()) builder.Configuration.AddUserSecrets<Program>(optional: true);
builder.Services.AddRazorPages(options => options.Conventions.AddPageRoute("/Inbox", "/"));
var trustedProxyIps = (builder.Configuration["AGGRO_TRUSTED_PROXY_IPS"] ?? "")
    .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
builder.Services.Configure<ForwardedHeadersOptions>(options => ForwardedProxyPolicy.Configure(options, trustedProxyIps));
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(IocRateLimit, context => LimitPerClient(context, 120));
    options.AddPolicy(RssRateLimit, context => LimitPerClient(context, 30));
    options.OnRejected = (context, _) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter = Math.Max(1, Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        return ValueTask.CompletedTask;
    };
});
var dataDirectory = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR") ?? Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(Path.Combine(dataDirectory, "keys"));
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDirectory, "keys")));
builder.Services.AddSingleton<AppDatabase>();
builder.Services.AddSingleton<IocCountCache>();
builder.Services.AddSingleton<ManualJobs>();
builder.Services.AddHostedService(services => services.GetRequiredService<ManualJobs>());
builder.Services.AddSingleton<AiModelSettingsService>();
builder.Services.AddSingleton<ArticleGroupingService>();
builder.Services.AddSingleton<OpenAiArticleGroupNameGenerator>();
builder.Services.AddHttpClient("ArticleGroupNames", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHostedService<ArticleGroupingWorker>();
builder.Services.AddSingleton<IBriefingWriter, OpenAiBriefingWriter>();
builder.Services.AddScoped<BriefingService>();
builder.Services.AddHostedService<BriefingScheduler>();
builder.Services.AddHttpClient("BriefingAI", client => client.Timeout = TimeSpan.FromMinutes(2));
builder.Services.AddSingleton<BackupManager>();
builder.Services.AddHostedService<BackupWorker>();
builder.Services.AddSingleton<SafePublicFetcher>();
builder.Services.AddSingleton<HomeFeedRoute>();
builder.Services.AddHttpClient<GitHubAdvisoryReader>(client => client.Timeout = TimeSpan.FromSeconds(30))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(10) });
builder.Services.AddTransient<FeedReader>();
builder.Services.AddHttpClient<AnalysisService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(90);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("ThreatIntelAggro/0.1 (+self-hosted research console)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(10) });
builder.Services.AddHttpClient(nameof(M365EndpointUpdater), client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHttpClient("OpenAIModels", client => client.Timeout = TimeSpan.FromSeconds(20));
if (!builder.Configuration.GetValue<bool>("ThreatIntelAggro:DisableExternalWorkers"))
{
    builder.Services.AddHostedService<FeedScheduler>();
    builder.Services.AddHostedService<AnalysisQueue>();
    builder.Services.AddHostedService<M365EndpointUpdater>();
}

var app = builder.Build();
var db = app.Services.GetRequiredService<AppDatabase>();
db.Initialize();
if (IocExclusionSettings.Get(db, "ai_settings_legacy_checked") is null)
{
    if (db.ScalarInt("SELECT COUNT(*) FROM feeds") > 0 && IocExclusionSettings.Get(db, "ai_model_settings") is null)
        IocExclusionSettings.Set(db, "ai_settings_legacy_pending", "true");
    IocExclusionSettings.Set(db, "ai_settings_legacy_checked", "true");
}
db.SeedUnit42();

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    var nonce = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18));
    context.Items["CspNonce"] = nonce;
    context.Response.Headers.ContentSecurityPolicy = $"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "same-origin";
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        var authorization = context.Request.Headers.Authorization.FirstOrDefault();
        if (!ApiKeySecurity.IsAuthorized(db, authorization))
        {
            context.Response.Headers.WWWAuthenticate = "Bearer";
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "A valid API bearer key is required." });
            return;
        }
    }
    await next();
});
app.UseAuthorization();
app.MapGet("/health", (AppDatabase database) =>
{
    try { database.ScalarInt("SELECT COUNT(*) FROM feeds"); return Results.Ok(new { status = "healthy" }); }
    catch { return Results.StatusCode(503); }
});
app.MapGet("/briefings/rss/{token}", (string token, HttpRequest request, HttpResponse response, AppDatabase database, BriefingService briefings) =>
{
    response.Headers.CacheControl = "no-store";
    var expected = IocExclusionSettings.Get(database, "briefing_rss_hash") ?? "";
    var supplied = BriefingService.HashFeedId(token);
    if (expected.Length != supplied.Length || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(expected), System.Text.Encoding.ASCII.GetBytes(supplied))) return Results.NotFound();
    var baseUrl = $"{request.Scheme}://{request.Host}";
    return Results.Text(briefings.ReadRss(baseUrl), "application/rss+xml; charset=utf-8");
}).RequireRateLimiting(RssRateLimit);
app.MapGet("/internal/manual-jobs/{key}", (string key, ManualJobs jobs, HttpResponse response) =>
{
    response.Headers.CacheControl = "no-store";
    return jobs.Status(key) is { } status ? Results.Json(status) : Results.NotFound();
});
app.MapGet("/internal/articles/status", (AppDatabase database) => Results.Json(database.Query("SELECT id,ai_status AS status,ai_error AS error FROM articles ORDER BY id DESC LIMIT 200").Select(x => new { id = x["id"], status = x["status"], error = x["error"] })));
app.MapGet("/api/iocs", (HttpRequest request, AppDatabase database) =>
{
    var daysText = request.Query["days"].FirstOrDefault() ?? request.Query["n"].FirstOrDefault();
    var days = int.TryParse(daysText, out var parsedDays) ? Math.Clamp(parsedDays, 1, 3650) : 7;
    var vendor = request.Query["vendor"].FirstOrDefault();
    var industry = request.Query["industry"].FirstOrDefault();
    var type = request.Query["type"].FirstOrDefault();
    var search = request.Query["search"].FirstOrDefault();
    var classification = request.Query["classification"].FirstOrDefault();
    var includeUnapproved = bool.TryParse(request.Query["includeUnapproved"].FirstOrDefault(), out var include) && include;
    var items = IocIndex.Read(database, days, vendor, industry, type, search, includeUnapproved: includeUnapproved, classification: classification);
    return Results.Json(new { generatedUtc = DateTimeOffset.UtcNow, query = new { days, vendor, industry, type, search, classification, includeUnapproved }, count = items.Count, items });
}).RequireRateLimiting(IocRateLimit);
app.MapRazorPages();
app.Run();

static RateLimitPartition<string> LimitPerClient(HttpContext context, int permitLimit)
{
    var address = context.Connection.RemoteIpAddress;
    if (address?.IsIPv4MappedToIPv6 == true) address = address.MapToIPv4();
    return RateLimitPartition.GetFixedWindowLimiter(address?.ToString() ?? "", _ => new FixedWindowRateLimiterOptions
    {
        PermitLimit = permitLimit,
        Window = TimeSpan.FromMinutes(1),
        QueueLimit = 0
    });
}
