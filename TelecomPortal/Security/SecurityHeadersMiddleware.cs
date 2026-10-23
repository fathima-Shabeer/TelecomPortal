namespace TelecomPortal.Security;

public class SecurityHeadersMiddleware(RequestDelegate next)
{
    public Task Invoke(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
        h["Cross-Origin-Opener-Policy"] = "same-origin";
        h["Cross-Origin-Resource-Policy"] = "same-origin";
        // Everything is hosted locally, so 'self' is enough. No inline scripts allowed.
        h["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
            "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; " +
            "form-action 'self'; frame-ancestors 'none'";

        // Don't cache authenticated pages
        if (ctx.User.Identity?.IsAuthenticated == true)
        {
            h["Cache-Control"] = "no-store";
            h["Pragma"] = "no-cache";
        }
        return next(ctx);
    }
}