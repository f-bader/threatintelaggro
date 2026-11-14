using ThreatIntelAggro;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
if (builder.Environment.IsDevelopment()) builder.Configuration.AddUserSecrets<Program>(optional: true);
builder.Services.AddRazorPages();
var dataDirectory = Environment.GetEnvironmentVariable("AGGRO_DATA_DIR") ?? Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(Path.Combine(dataDirectory, "keys"));
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDirectory, "keys")));
builder.Services.AddSingleton<AppDatabase>();
builder.Services.AddHttpClient<FeedReader>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(25);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("ThreatIntelAggro/0.1 (+self-hosted RSS reader)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    PooledConnectionLifetime = TimeSpan.FromMinutes(10)
});
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

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapGet("/health", (AppDatabase database) =>
{
    try { database.ScalarInt("SELECT COUNT(*) FROM feeds"); return Results.Ok(new { status = "healthy" }); }
    catch { return Results.StatusCode(503); }
});
app.MapGet("/api/articles/status", (AppDatabase database) => Results.Json(database.Query("SELECT id,ai_status AS status,ai_error AS error FROM articles ORDER BY id DESC LIMIT 200").Select(x => new { id = x["id"], status = x["status"], error = x["error"] })));
app.MapGet("/api/iocs", (HttpRequest request, AppDatabase database) =>
{
    var daysText = request.Query["days"].FirstOrDefault() ?? request.Query["n"].FirstOrDefault();
    var days = int.TryParse(daysText, out var parsedDays) ? Math.Clamp(parsedDays, 1, 3650) : 7;
    var vendor = request.Query["vendor"].FirstOrDefault();
    var industry = request.Query["industry"].FirstOrDefault();
    var type = request.Query["type"].FirstOrDefault();
    var search = request.Query["search"].FirstOrDefault();
    var includeUnapproved = bool.TryParse(request.Query["includeUnapproved"].FirstOrDefault(), out var include) && include;
    var items = IocIndex.Read(database, days, vendor, industry, type, search, includeUnapproved: includeUnapproved);
    return Results.Json(new { generatedUtc = DateTimeOffset.UtcNow, query = new { days, vendor, industry, type, search, includeUnapproved }, count = items.Count, items });
});
app.MapRazorPages();
app.Run();
