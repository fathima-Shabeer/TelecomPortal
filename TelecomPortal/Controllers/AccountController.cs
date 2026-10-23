using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using TelecomPortal.Models;
using TelecomPortal.Security;

namespace TelecomPortal.Controllers;

public class AccountController(
    SignInManager<ApplicationUser> signIn,
    UserManager<ApplicationUser> users,
    IAuditService audit) : Controller
{
    private const string Issuer = "TelecomPortal";

    // ---------------- Login ----------------
    [HttpGet, AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View(new LoginViewModel());
    }

    [HttpPost, AllowAnonymous, EnableRateLimiting("auth")]
    public async Task<IActionResult> Login(LoginViewModel m, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        if (!ModelState.IsValid) return View(m);

        var result = await signIn.PasswordSignInAsync(m.Email, m.Password, m.RememberMe, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            await audit.LogAsync("LoginSuccess", m.Email);
            return LocalRedirectOrHome(returnUrl);
        }
        if (result.RequiresTwoFactor)
            return RedirectToAction(nameof(LoginWith2fa), new { returnUrl, rememberMe = m.RememberMe });

        if (result.IsLockedOut)
        {
            await audit.LogAsync("AccountLockedOut", m.Email);
            return View("Lockout");
        }

        await audit.LogAsync("LoginFailed", m.Email);
        // Generic message: don't reveal whether the email exists
        ModelState.AddModelError("", "Invalid email or password.");
        return View(m);
    }

    // ---------------- 2FA login ----------------
    [HttpGet, AllowAnonymous]
    public async Task<IActionResult> LoginWith2fa(bool rememberMe, string? returnUrl = null)
    {
        if (await signIn.GetTwoFactorAuthenticationUserAsync() is null)
            return RedirectToAction(nameof(Login));

        ViewData["ReturnUrl"] = returnUrl;
        return View(new TwoFactorViewModel { RememberMe = rememberMe });
    }

    [HttpPost, AllowAnonymous, EnableRateLimiting("auth")]
    public async Task<IActionResult> LoginWith2fa(TwoFactorViewModel m, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        if (!ModelState.IsValid) return View(m);

        var user = await signIn.GetTwoFactorAuthenticationUserAsync();
        if (user is null) return RedirectToAction(nameof(Login));

        var code = m.Code.Replace(" ", "").Replace("-", "");
        var result = await signIn.TwoFactorAuthenticatorSignInAsync(
            code, m.RememberMe, rememberClient: false);

        if (result.Succeeded)
        {
            await audit.LogAsync("Login2faSuccess", user.UserName);
            return LocalRedirectOrHome(returnUrl);
        }
        if (result.IsLockedOut)
        {
            await audit.LogAsync("AccountLockedOut", user.UserName);
            return View("Lockout");
        }

        await audit.LogAsync("Login2faFailed", user.UserName);
        ModelState.AddModelError("", "Invalid authenticator code.");
        return View(m);
    }

    [HttpGet, AllowAnonymous]
    public async Task<IActionResult> LoginWithRecoveryCode(string? returnUrl = null)
    {
        if (await signIn.GetTwoFactorAuthenticationUserAsync() is null)
            return RedirectToAction(nameof(Login));

        ViewData["ReturnUrl"] = returnUrl;
        return View(new RecoveryCodeViewModel());
    }

    [HttpPost, AllowAnonymous, EnableRateLimiting("auth")]
    public async Task<IActionResult> LoginWithRecoveryCode(RecoveryCodeViewModel m, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        if (!ModelState.IsValid) return View(m);

        var user = await signIn.GetTwoFactorAuthenticationUserAsync();
        if (user is null) return RedirectToAction(nameof(Login));

        var result = await signIn.TwoFactorRecoveryCodeSignInAsync(m.RecoveryCode.Replace(" ", ""));
        if (result.Succeeded)
        {
            await audit.LogAsync("LoginRecoveryCodeUsed", user.UserName);
            return LocalRedirectOrHome(returnUrl);
        }
        if (result.IsLockedOut) return View("Lockout");

        await audit.LogAsync("LoginRecoveryCodeFailed", user.UserName);
        ModelState.AddModelError("", "Invalid recovery code.");
        return View(m);
    }

    // ---------------- Enable 2FA ----------------
    [HttpGet, Authorize]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        return View(await BuildAuthenticatorModel(user));
    }

    [HttpPost, Authorize]
    public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel m)
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();

        if (!ModelState.IsValid)
            return View(await BuildAuthenticatorModel(user, m.Code));

        var code = m.Code.Replace(" ", "").Replace("-", "");
        var valid = await users.VerifyTwoFactorTokenAsync(
            user, users.Options.Tokens.AuthenticatorTokenProvider, code);

        if (!valid)
        {
            ModelState.AddModelError(nameof(m.Code), "Verification code is invalid.");
            return View(await BuildAuthenticatorModel(user));
        }

        await users.SetTwoFactorEnabledAsync(user, true);
        await audit.LogAsync("TwoFactorEnabled", user.UserName);

        var codes = await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        var model = await BuildAuthenticatorModel(user);
        model.RecoveryCodes = codes?.ToArray();   // shown once, store them safely
        return View(model);
    }

    // ---------------- Logout / denied ----------------
    [HttpPost, Authorize]
    public async Task<IActionResult> Logout()
    {
        await audit.LogAsync("Logout", User.Identity?.Name);
        await signIn.SignOutAsync();
        return RedirectToAction(nameof(Login));
    }

    [HttpGet, AllowAnonymous]
    public IActionResult AccessDenied() => View();

    // ---------------- Helpers ----------------
    private IActionResult LocalRedirectOrHome(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl)   // blocks open redirects
            ? LocalRedirect(returnUrl)
            : RedirectToAction("Index", "Dashboard", new { area = "Admin" });

    private async Task<EnableAuthenticatorViewModel> BuildAuthenticatorModel(
        ApplicationUser user, string code = "")
    {
        var key = await users.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await users.ResetAuthenticatorKeyAsync(user);
            key = await users.GetAuthenticatorKeyAsync(user);
        }

        return new EnableAuthenticatorViewModel
        {
            SharedKey = FormatKey(key!),
            AuthenticatorUri =
                $"otpauth://totp/{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(user.Email!)}" +
                $"?secret={key}&issuer={Uri.EscapeDataString(Issuer)}&digits=6",
            Code = code
        };
    }

    private static string FormatKey(string key)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < key.Length; i += 4)
            sb.Append(key.AsSpan(i, Math.Min(4, key.Length - i))).Append(' ');
        return sb.ToString().Trim().ToLowerInvariant();
    }
}