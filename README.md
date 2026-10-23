# TelecomPortal

An offline-first telecom self-service and admin portal built with **ASP.NET Core (.NET 10)**, focused on **secure-by-design** engineering: mandatory 2FA for admins, automatic audit trails, rate limiting, and OWASP protections.

> **Disclaimer:** This is an independent portfolio project. It is not affiliated with, endorsed by, or connected to any telecom operator. All brand names, plans, prices, and images are fictional demo data.

---

## Highlights

- **Runs fully offline:** SQLite database, locally hosted assets, no CDNs, no external APIs. Clone, restore, run.
- **Security first:** TOTP two-factor authentication, account lockout, role-based access, audit log, rate limiting, strict CSP and security headers.
- **Data-driven UI:** hero banners, plans, and app-store items are managed from the admin panel, not hard-coded.
- **Clean structure:** MVC with a dedicated `Admin` area, services, and an EF Core interceptor for cross-cutting concerns.


## Tech stack

| Layer | Technology |
|---|---|
| Framework | ASP.NET Core MVC, .NET 10, C# 14 |
| Data | Entity Framework Core + SQLite |
| Auth | ASP.NET Core Identity, cookie authentication, TOTP 2FA |
| Frontend | Razor views, Bootstrap, Swiper (all hosted locally) |
| Testing | xUnit, `WebApplicationFactory` |

## Features and status

**Security (implemented)**
- [x] ASP.NET Core Identity with 12+ character password policy
- [x] Account lockout (5 failed attempts, 15 minutes)
- [x] TOTP two-factor authentication with recovery codes
- [x] 2FA required for the Admin role
- [x] Role-based authorization (`Admin`, `Support`)
- [x] Automatic audit log of every insert, update, and delete (EF Core `SaveChangesInterceptor`), with secrets masked
- [x] Audit of login, logout, lockout, and 2FA events
- [x] Rate limiting: global, strict on login/2FA, limited on public forms
- [x] CSRF protection on all state-changing requests
- [x] Secure `__Host-` cookies, HSTS, HTTPS redirection
- [x] Security headers and strict Content Security Policy
- [x] Open-redirect protection, generic login errors (no user enumeration)

**Portal (in progress)**
- [ ] Home page with data-driven hero carousel and thumbnail navigation
- [ ] Admin: banner management with validated image upload
- [ ] Plans catalog with filters and detail pages
- [ ] Business app store with search and categories
- [ ] Contact Sales form with admin review and CSV export
- [ ] Customer accounts: subscription and usage overview
- [ ] Mock recharge and payment flow with transaction history
- [ ] English / Arabic (RTL) localization
- [ ] Automated tests

## Architecture

```
TelecomPortal/
  Program.cs                      Service registration and middleware pipeline
  Models/                         Entities and view models
  Data/                           DbContext, audit interceptor, seeding
  Security/                       Audit service, security headers, 2FA filter
  Controllers/                    Public and account controllers
  Areas/Admin/                    Role-protected admin panel
  Views/ , wwwroot/               Razor views and local static assets
```

**Key design decisions**
- **Audit via EF Core interceptor:** every data change is logged in one place, so no controller can forget to audit.
- **Layered brute-force defense:** rate limiting slows attackers by IP, while lockout protects each account.
- **2FA enforced by an authorization filter:** admins cannot reach any admin page until 2FA is set up.
- **Offline by design:** a strict `'self'`-only CSP is possible because no third-party scripts, fonts, or styles are used.
- **Secrets outside source control:** the seeded admin credentials come from user-secrets.

## Getting started

**Prerequisites:** Visual Studio 2026 (or the .NET 10 SDK) and Git.

```bash
git clone https://github.com/<your-username>/TelecomPortal.git
cd TelecomPortal

# Trust the local HTTPS certificate
dotnet dev-certs https --trust

# Set the seeded admin credentials (never commit these)
dotnet user-secrets init
dotnet user-secrets set "SeedAdmin:Email" "admin@portal.local"
dotnet user-secrets set "SeedAdmin:Password" "<a strong 12+ character password>"

# Create the database and run
dotnet ef database update
dotnet run
```

Then open `https://localhost:<port>/Account/Login`, sign in, and complete the 2FA setup (add the displayed key to any authenticator app and save your recovery codes).

## Security testing checklist

1. Fail the password 5 times and confirm the account locks.
2. Send more than 5 login requests in a minute and confirm HTTP 429.
3. Sign in as a non-admin and confirm `/Admin` returns access denied.
4. Sign in as an admin without 2FA and confirm you are redirected to setup.
5. Edit any record and confirm a row appears in `/Admin/Audit` with sensitive fields masked.

## OWASP Top 10 coverage

| Risk | Mitigation |
|---|---|
| A01 Broken access control | Role-based authorization, admin base controller, local-only redirects |
| A02 Cryptographic failures | Identity password hashing, HTTPS/HSTS, persisted Data Protection keys |
| A03 Injection | EF Core parameterized queries, Razor output encoding, strict CSP |
| A04 Insecure design | Mandatory admin 2FA, lockout, rate limits |
| A05 Security misconfiguration | Security headers, no server banner, no stack traces in production |
| A06 Vulnerable components | `dotnet list package --vulnerable` |
| A07 Authentication failures | Password policy, lockout, TOTP 2FA, recovery codes |
| A08 Integrity failures | Anti-forgery tokens, no external scripts |
| A09 Logging failures | Automatic audit trail plus security event logging |
| A10 SSRF | No outbound requests from the application |

## Roadmap

- Event-driven subscription and payment flow (MassTransit)
- PostgreSQL / SQL Server provider and Redis-backed rate limiting for multi-instance deployment
- Docker Compose and CI pipeline (build, test, vulnerability scan)
- Azure deployment

