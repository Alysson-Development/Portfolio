using System.Security.Claims;
using System.Threading.RateLimiting;
using Amazon.Runtime;
using Amazon.S3;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Portfolio.Components;
using Portfolio.Data;
using Portfolio.Services;

var builder = WebApplication.CreateBuilder(args);

var storagePathSetting = builder.Configuration["Portfolio:StoragePath"] ?? ".";
var storageRoot = Path.GetFullPath(
    storagePathSetting,
    builder.Environment.ContentRootPath);

Directory.CreateDirectory(storageRoot);

var connectionString = builder.Configuration.GetConnectionString("Portfolio");

if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        "ConnectionStrings:Portfolio não configurada.");
}

builder.Services.AddRazorComponents().AddInteractiveServerComponents();

var r2Endpoint = builder.Configuration["R2:Endpoint"]
                 ?? throw new InvalidOperationException("R2:Endpoint não configurado.");

var r2AccessKey = builder.Configuration["R2:AccessKey"]
                  ?? throw new InvalidOperationException("R2:AccessKey não configurado.");

var r2SecretKey = builder.Configuration["R2:SecretKey"]
                  ?? throw new InvalidOperationException("R2:SecretKey não configurado.");

var r2Credentials = new BasicAWSCredentials(r2AccessKey, r2SecretKey);

builder.Services.AddSingleton<IAmazonS3>(_ =>
{
    var config = new AmazonS3Config
    {
        ServiceURL = r2Endpoint,
        ForcePathStyle = true
    };

    return new AmazonS3Client(r2Credentials, config);
});

builder.Services.AddScoped<IStorageService, R2StorageService>();

builder.Services.AddPooledDbContextFactory<PortfolioDbContext>(o =>
    o.UseNpgsql(connectionString));

builder.Services.AddScoped<IPortfolioContentService, PortfolioContentService>();
builder.Services.AddSingleton<IPasswordHasher<string>, PasswordHasher<string>>();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1;
    if (builder.Environment.IsProduction())
    {
        // Render's proxy addresses can change; the container is reached publicly through Render's proxy.
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();
    }
});
var configuredAdminPassword = builder.Configuration["Admin:Password"];
var adminPasswordHash = string.IsNullOrEmpty(configuredAdminPassword)
    ? null
    : new PasswordHasher<string>().HashPassword("admin", configuredAdminPassword);
builder.Services.AddSingleton(new AdminPasswordHash(adminPasswordHash ?? string.Empty));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.LoginPath = "/admin/login";
    o.Cookie.Name = "Portfolio.Admin";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = builder.Environment.IsProduction()
        ? CookieSecurePolicy.Always
        : CookieSecurePolicy.SameAsRequest;
    o.SlidingExpiration = true;
    o.ExpireTimeSpan = TimeSpan.FromHours(8);
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(o => o.AddFixedWindowLimiter("admin-login", x =>
{
    x.PermitLimit = 5;
    x.Window = TimeSpan.FromMinutes(5);
    x.QueueLimit = 0;
}));
var app = builder.Build();
app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseWhen(context => !context.Request.Path.Equals("/health", StringComparison.OrdinalIgnoreCase),
    branch => branch.UseHttpsRedirection());

app.UseStaticFiles();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/admin") && !ctx.Request.Path.StartsWithSegments("/admin/login") &&
        !ctx.Request.Path.StartsWithSegments("/admin/session") && !(ctx.User.Identity?.IsAuthenticated ?? false))
    {
        ctx.Response.Redirect("/admin/login");
        return;
    }

    await next();
});
app.MapPost("/admin/session", async (HttpContext ctx, IServiceProvider services, IPasswordHasher<string> hasher) =>
{
    var storedHash = services.GetRequiredService<AdminPasswordHash>().Value;
    if (string.IsNullOrEmpty(storedHash))
        return Results.Problem("Configure Admin__Password no ambiente antes do login.", statusCode: 503);
    var form = await ctx.Request.ReadFormAsync();
    var candidate = form["password"].ToString();
    if (hasher.VerifyHashedPassword("admin", storedHash, candidate) == PasswordVerificationResult.Failed)
        return Results.Redirect("/admin/login?error=1");
    var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin")],
        CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    return Results.Redirect("/admin");
}).RequireRateLimiting("admin-login");
app.MapPost("/admin/logout", async (HttpContext c) =>
{
    await c.SignOutAsync();
    return Results.Redirect("/admin/login");
});
app.MapPost("/admin/upload/{kind}", async (
    string kind,
    HttpRequest request,
    IStorageService storage) =>
{
    var form = await request.ReadFormAsync();

    var file = form.Files.GetFile("file");

    if (file is null)
        return Results.BadRequest("Arquivo ausente.");

    var imageKinds = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        "projects",
        "education", 
        "profile",
        "technologies"
    };

    var isCv = string.Equals(
        kind,
        "cv",
        StringComparison.OrdinalIgnoreCase);

    if (!isCv && !imageKinds.Contains(kind))
        return Results.BadRequest("Tipo de arquivo inválido.");

    const long maxImageSize = 5_242_880;
    const long maxCvSize = 10_485_760;
    
    var maxSize = isCv
        ? maxCvSize
        : maxImageSize;

    
    if (file.Length < 1 || file.Length > maxSize)
    {
        return Results.BadRequest(
            isCv
                ? "O currículo deve ser um PDF de até 10 MB."
                : "A imagem deve ter no máximo 5 MB.");
    }

    var extension = Path
        .GetExtension(file.FileName)
        .ToLowerInvariant();

    await using var input = file.OpenReadStream();

    using var memory = new MemoryStream();

    await input.CopyToAsync(memory);

    var bytes = memory.ToArray();

    string mime;

    if (isCv)
    {
        if (extension != ".pdf" ||
            !string.Equals(
                file.ContentType,
                "application/pdf",
                StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(
                "O currículo deve estar no formato PDF.");
        }

        var validPdf =
            bytes.Length >= 4 &&
            bytes[0] == 0x25 &&
            bytes[1] == 0x50 &&
            bytes[2] == 0x44 &&
            bytes[3] == 0x46;

        if (!validPdf)
        {
            return Results.BadRequest(
                "O conteúdo do arquivo não corresponde a um PDF válido.");
        }

        mime = "application/pdf";
    }
    else
    {
        var allowed = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase)
        {
            [".png"] = "image/png",
            [".jpg"] = "image/jpeg",
            [".jpeg"] = "image/jpeg",
            [".webp"] = "image/webp"
        };

        if (!allowed.TryGetValue(extension, out mime!) ||
            !string.Equals(
                file.ContentType,
                mime,
                StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(
                "Formato de imagem inválido.");
        }

        var valid = extension == ".png"
            ? bytes.Length >= 8 &&
              bytes.AsSpan().StartsWith(
                  new byte[]
                  {
                      137, 80, 78, 71,
                      13, 10, 26, 10
                  })

            : extension == ".webp"
                ? bytes.Length >= 12 &&
                  System.Text.Encoding.ASCII.GetString(
                      bytes,
                      0,
                      4) == "RIFF" &&
                  System.Text.Encoding.ASCII.GetString(
                      bytes,
                      8,
                      4) == "WEBP"

                : bytes.Length >= 4 &&
                  bytes[0] == 255 &&
                  bytes[1] == 216 &&
                  bytes[^2] == 255 &&
                  bytes[^1] == 217;

        if (!valid)
        {
            return Results.BadRequest(
                "O conteúdo não corresponde a uma imagem válida.");
        }
    }

    await using var uploadStream =
        new MemoryStream(bytes);

    var url = await storage.UploadAsync(
        uploadStream,
        file.FileName,
        mime,
        kind,
        request.HttpContext.RequestAborted);

    return Results.Ok(new { url });
}).RequireAuthorization();
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
using (var scope = app.Services.CreateScope())
{
    var factory = scope.ServiceProvider
        .GetRequiredService<IDbContextFactory<PortfolioDbContext>>();

    await using var db = await factory.CreateDbContextAsync();

    await db.Database.MigrateAsync();
}

app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
