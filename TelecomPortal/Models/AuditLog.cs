namespace TelecomPortal.Models;

public class AuditLog
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string? UserId { get; set; }
    public string UserName { get; set; } = "system";
    public string Action { get; set; } = string.Empty;      // Added, Modified, Deleted, LoginSuccess, ...
    public string? EntityName { get; set; }
    public string? EntityKey { get; set; }
    public string? Changes { get; set; }                     // JSON
    public string? IpAddress { get; set; }
}