using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using TelecomPortal.Models;

namespace TelecomPortal.Security;

public class RequireTwoFactorAttribute : TypeFilterAttribute
{
    public RequireTwoFactorAttribute() : base(typeof(RequireTwoFactorFilter)) { }
}

public class RequireTwoFactorFilter(UserManager<ApplicationUser> users) : IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext ctx)
    {
        if (ctx.HttpContext.User.Identity?.IsAuthenticated != true) return;

        var user = await users.GetUserAsync(ctx.HttpContext.User);
        if (user is null || !user.TwoFactorEnabled)
            ctx.Result = new RedirectToActionResult("EnableAuthenticator", "Account", new { area = "" });
    }
}