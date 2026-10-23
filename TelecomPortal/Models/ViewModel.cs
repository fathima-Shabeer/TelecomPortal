using System.ComponentModel.DataAnnotations;

namespace TelecomPortal.Models;

public class LoginViewModel
{
    [Required, EmailAddress] public string Email { get; set; } = "";
    [Required, DataType(DataType.Password)] public string Password { get; set; } = "";
    public bool RememberMe { get; set; }
}

public class TwoFactorViewModel
{
    [Required, StringLength(7, MinimumLength = 6), Display(Name = "Authenticator code")]
    public string Code { get; set; } = "";
    public bool RememberMe { get; set; }
}

public class RecoveryCodeViewModel
{
    [Required, Display(Name = "Recovery code")]
    public string RecoveryCode { get; set; } = "";
}

public class EnableAuthenticatorViewModel
{
    public string SharedKey { get; set; } = "";
    public string AuthenticatorUri { get; set; } = "";
    [Required, StringLength(7, MinimumLength = 6), Display(Name = "Verification code")]
    public string Code { get; set; } = "";
    public string[]? RecoveryCodes { get; set; }
}