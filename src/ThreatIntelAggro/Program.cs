using ThreatIntelAggro;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net;

var builder = WebApplication.CreateBuilder(args);
if (builder.Environment.IsDevelopment()) builder.Configuration.AddUserSecrets<Program>(optional: true);
builder.Services.AddRazorPages();
var trustedProxyIps = (builder.Configuration["AGGRO_TRUSTED_PROXY_IPS"] ?? "")
    .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
builder.Services.Configure<ForwardedHeadersOptions>(options => ForwardedProxyPolicy.Configure(options, trustedProxyIps));
var dataDirectory = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR") ?? Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(Path.Combine(dataDirectory, "keys"));
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDirectory, "keys")));
builder.Services.AddSingleton<AppDatabase>();
builder.Services.AddSingleton<SafePublicFetcher>();
builder.Services.AddTransient<FeedReader>();
builder.Services.AddHttpClient<AnalysisService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(90);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("ThreatIntelAggro/0.1 (+self-hosted research console)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(10) });
builder.Services.AddHttpClient(nameof(M365EndpointUpdater), client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHostedService<FeedScheduler>();
builder.Services.AddHostedService<AnalysisQueue>();
builder.Services.AddHostedService<M365EndpointUpdater>();

var app = builder.Build();
var db = app.Services.GetRequiredService<AppDatabase>();
db.Initialize();
db.SeedUnit42();

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseStaticFiles();
app.UseRouting();
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
});
app.MapRazorPages();
app.Run();
