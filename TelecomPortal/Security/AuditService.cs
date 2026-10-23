using System.Security.Claims;
using TelecomPortal.Data;
using TelecomPortal.Models;

namespace TelecomPortal.Security;

public interface IAuditService
{
    Task LogAsync(string action, string? userName, string? details = null);
}

public class AuditService(AppDbContext db, IHttpContextAccessor http) : IAuditService
{
    public async Task LogAsync(string action, string? userName, string? details = null)
    {
        var ctx = http.HttpContext;
        db.AuditLogs.Add(new AuditLog
        {
            Action = action,
            UserName = userName ?? ctx?.User.Identity?.Name ?? "anonymous",
            UserId = ctx?.User.FindFirstValue(ClaimTypes.NameIdentifier),
            IpAddress = ctx?.Connection.RemoteIpAddress?.ToString(),
            Changes = details
        });
        await db.SaveChangesAsync();
    }
}