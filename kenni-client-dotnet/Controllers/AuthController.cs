using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KenniSampleApp.Controllers;

public class AuthController : Controller
{
    [HttpGet("/auth/login")]
    public IActionResult Login() =>
        Challenge(
            new AuthenticationProperties { RedirectUri = "/" },
            OpenIdConnectDefaults.AuthenticationScheme);

    // Local sign-out only — Kenni's session cookie is untouched, so the next
    // sign-in is silent. Use /auth/rp-logout to also end Kenni's session.
    [Authorize]
    [HttpPost("/auth/logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }

    // RP-initiated logout: clear the local cookie first, then redirect to
    // Kenni's end_session_endpoint with id_token_hint + post_logout_redirect_uri.
    // Order matters — if the Kenni redirect fails, the local session is still
    // cleared.
    [Authorize]
    [HttpPost("/auth/rp-logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RpLogout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            OpenIdConnectDefaults.AuthenticationScheme);
    }
}
