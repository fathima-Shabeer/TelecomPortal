using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TelecomPortal.Data;
using TelecomPortal.Models;
using TelecomPortal.Security;

var builder = WebApplication.CreateBuilder(args);
Directory.CreateDirectory("App_Data");

// Hide "Server: Kestrel" header
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);

// ---------- Database + audit interceptor ----------
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditSaveChangesInterceptor>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddDbContext<AppDbContext>((sp, o) =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default"))
     .AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>()));

// ---------- Identity: password policy, lockout ----------
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(o =>
{
    o.Password.RequiredLength = 12;
    o.Password.RequireDigit = true;
    o.Password.RequireLowercase = true;
    o.Password.RequireUppercase = true;
    o.Password.RequireNonAlphanumeric = true;
    o.Password.RequiredUniqueChars = 5;

    o.Lockout.AllowedForNewUsers = true;
    o.Lockout.MaxFailedAccessAttempts = 5;
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);

    o.User.RequireUniqueEmail = true;
    o.SignIn.RequireConfirmedAccount = false;   // no email server offline
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// Role/permission changes take effect within a minute
builder.Services.Configure<SecurityStampValidatorOptions>(o =>
    o.ValidationInterval = TimeSpan.FromMinutes(1));

// ---------- Secure cookies ----------
builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/Account/Login";
    o.AccessDeniedPath = "/Account/AccessDenied";
    o.Cookie.Name = "__Host-portal-auth";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    o.SlidingExpiration = true;
});

builder.Services.AddAntiforgery(o =>
{
    o.Cookie.Name = "__Host-portal-csrf";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Strict;
});

// Keep keys on disk so cookies and 2FA survive restarts
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, "App_Data", "keys")))
    .SetApplicationName("TelecomPortal");

// ---------- Rate limiting ----------
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Global: 100 requests/min per IP
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        RateLimitPartition.GetSlidingWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6,
                QueueLimit = 0
            }));

    // Login / 2FA: 5 attempts/min per IP (brute-force protection)
    o.AddPolicy("auth", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    // Public forms (Contact Sales): 3 per 10 min per IP
    o.AddPolicy("form", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 3,
                Window = TimeSpan.FromMinutes(10),
                QueueLimit = 0
            }));
});

// ---------- MVC: CSRF on every POST/PUT/DELETE ----------
builder.Services.AddControllersWithViews(o =>
    o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

var app = builder.Build();

// ---------- Pipeline (order matters) ----------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");   // no stack traces to users
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute("areas", "{area:exists}/{controller=Dashboard}/{action=Index}/{id?}");
app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");

using (var scope = app.Services.CreateScope())
    await DbInitializer.SeedAsync(scope.ServiceProvider, app.Configuration);

app.Run();