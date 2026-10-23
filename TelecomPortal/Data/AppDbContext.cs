using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection.Emit;
using TelecomPortal.Models;

namespace TelecomPortal.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);
        b.Entity<AuditLog>(e =>
        {
            e.HasIndex(x => x.TimestampUtc);
            e.HasIndex(x => x.UserName);
            e.Property(x => x.UserName).HasMaxLength(256);
            e.Property(x => x.Action).HasMaxLength(64);
            e.Property(x => x.EntityName).HasMaxLength(128);
            e.Property(x => x.EntityKey).HasMaxLength(128);
            e.Property(x => x.IpAddress).HasMaxLength(64);
        });
    }
}