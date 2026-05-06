using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KenniSampleApp.Controllers;

// Bearer-protected resource. Token validation (signature via JWKS, issuer,
// audience, expiry) is wired up in Program.cs via AddJwtBearer; the
// "ApiScope" policy additionally requires the configured KENNI_API_SCOPE
// to be present on the token.
[ApiController]
[Route("api/protected-resource")]
[Authorize(Policy = "ApiScope", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class ProtectedResourceController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var sub = User.FindFirst("sub")?.Value;
        var nationalId = User.FindFirst("national_id")?.Value;
        var scopes = (User.FindFirst("scope")?.Value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var expValue = User.FindFirst("exp")?.Value;
        DateTime? expiresAt = long.TryParse(expValue, out var exp)
            ? DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime
            : null;

        return Ok(new
        {
            message = "Halló!",
            served_by = "ASP.NET Core (.NET 10) example",
            sub,
            national_id = nationalId,
            scopes,
            expires_at = expiresAt,
        });
    }
}
