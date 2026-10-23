using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using TelecomPortal.Models;

namespace TelecomPortal.Data;

public sealed class AuditSaveChangesInterceptor(IHttpContextAccessor http) : SaveChangesInterceptor
{
    // Never write secrets into the audit trail (Value = Identity token rows, incl. the 2FA key)
    private static readonly HashSet<string> Sensitive = new(StringComparer.OrdinalIgnoreCase)
        { "PasswordHash", "SecurityStamp", "ConcurrencyStamp", "Value" };

    public override InterceptionResult<int> SavingChanges(DbContextEventData e, InterceptionResult<int> result)
    {
        Audit(e.Context);
        return base.SavingChanges(e, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData e, InterceptionResult<int> result, CancellationToken ct = default)
    {
        Audit(e.Context);
        return base.SavingChangesAsync(e, result, ct);
    }

    private void Audit(DbContext? ctx)
    {
        if (ctx is null) return;

        var httpCtx = http.HttpContext;
        var userName = httpCtx?.User.Identity?.Name ?? "system";
        var userId = httpCtx?.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var ip = httpCtx?.Connection.RemoteIpAddress?.ToString();

        var entries = ctx.ChangeTracker.Entries()
            .Where(x => x.Entity is not AuditLog
                     && x.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
            .ToList();

        foreach (var entry in entries)
        {
            var key = string.Join(",", entry.Properties
                .Where(p => p.Metadata.IsPrimaryKey())
                .Select(p => p.CurrentValue ?? p.OriginalValue));

            ctx.Set<AuditLog>().Add(new AuditLog
            {
                UserId = userId,
                UserName = userName,
                IpAddress = ip,
                Action = entry.State.ToString(),
                EntityName = entry.Metadata.ClrType.Name,
                EntityKey = key,
                Changes = JsonSerializer.Serialize(BuildChanges(entry))
            });
        }
    }

    private static Dictionary<string, object?> BuildChanges(EntityEntry entry)
    {
        var d = new Dictionary<string, object?>();
        foreach (var p in entry.Properties)
        {
            var name = p.Metadata.Name;
            if (Sensitive.Contains(name)) { d[name] = "***"; continue; }

            switch (entry.State)
            {
                case EntityState.Added:
                    d[name] = p.CurrentValue;
                    break;
                case EntityState.Deleted:
                    d[name] = p.OriginalValue;
                    break;
                case EntityState.Modified when p.IsModified:
                    d[name] = new { Old = p.OriginalValue, New = p.CurrentValue };
                    break;
            }
        }
        return d;
    }
}