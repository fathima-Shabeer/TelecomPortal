using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TelecomPortal.Models;

namespace TelecomPortal.Data;

public static class DbInitializer
{
    public static readonly string[] Roles = ["Admin", "Support"];

    public static async Task SeedAsync(IServiceProvider sp, IConfiguration cfg)
    {
        var db = sp.GetRequiredService<AppDbContext>();
        await db.Database.MigrateAsync();

        var roleMgr = sp.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var r in Roles)
            if (!await roleMgr.RoleExistsAsync(r))
                await roleMgr.CreateAsync(new IdentityRole(r));

        var email = cfg["SeedAdmin:Email"];
        var password = cfg["SeedAdmin:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)) return;

        var userMgr = sp.GetRequiredService<UserManager<ApplicationUser>>();
        if (await userMgr.FindByEmailAsync(email) is not null) return;

        var admin = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            FullName = "Portal Administrator"
        };

        var result = await userMgr.CreateAsync(admin, password);
        if (result.Succeeded)
            await userMgr.AddToRoleAsync(admin, "Admin");
        else
            throw new InvalidOperationException(
                "Seeding admin failed: " + string.Join("; ", result.Errors.Select(e => e.Description)));
    }
}