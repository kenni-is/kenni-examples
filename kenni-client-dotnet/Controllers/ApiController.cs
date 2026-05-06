using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KenniSampleApp.Controllers;

[ApiController]
[Route("api")]
public class ApiController : ControllerBase
{
    private readonly KenniOptions _kenni;
    private readonly IHttpClientFactory _httpFactory;

    public ApiController(IOptions<KenniOptions> kenni, IHttpClientFactory httpFactory)
    {
        _kenni = kenni.Value;
        _httpFactory = httpFactory;
    }

    // Server-side proxy: pulls the user's stored Kenni access token from the
    // OIDC cookie and uses it to call our own /api/protected-resource. Done
    // server-side so the access token never reaches the browser.
    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        if (!_kenni.ApiEnabled)
            return StatusCode(503, new { error = "KENNI_API_SCOPE is not configured on this app." });

        var accessToken = await HttpContext.GetTokenAsync("access_token");
        if (string.IsNullOrEmpty(accessToken))
            return StatusCode(500, new { error = "No access token in OIDC session." });

        var origin = $"{Request.Scheme}://{Request.Host}";
        using var client = _httpFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{origin}/api/protected-resource");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await client.SendAsync(req);
        var body = await response.Content.ReadAsStringAsync();
        return new ContentResult
        {
            Content = body,
            ContentType = "application/json",
            StatusCode = (int)response.StatusCode,
        };
    }

    // Client-credentials grant — straight POST to Kenni's token endpoint with
    // HTTP Basic auth (RFC 6749 §2.3.1). Returns the decoded JWT claims so
    // the demo proves the grant worked.
    [HttpPost("client-credentials")]
    public async Task<IActionResult> ClientCredentials()
    {
        if (!_kenni.M2MEnabled)
            return StatusCode(503, new
            {
                error = "Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE.",
            });

        using var client = _httpFactory.CreateClient();

        // Discover token_endpoint each time (no caching for this demo).
        using var discoveryResp = await client.GetAsync(
            $"{_kenni.Issuer}/.well-known/openid-configuration");
        discoveryResp.EnsureSuccessStatusCode();
        using var discoveryDoc = JsonDocument.Parse(await discoveryResp.Content.ReadAsStringAsync());
        var tokenEndpoint = discoveryDoc.RootElement.GetProperty("token_endpoint").GetString()!;

        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(_kenni.M2MClientId!)}:{Uri.EscapeDataString(_kenni.M2MClientSecret!)}"));

        var tokenReq = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        tokenReq.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        tokenReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        tokenReq.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = _kenni.M2MScope!,
        });

        using var tokenResp = await client.SendAsync(tokenReq);
        var tokenBody = await tokenResp.Content.ReadAsStringAsync();

        if (!tokenResp.IsSuccessStatusCode)
            return StatusCode((int)tokenResp.StatusCode, new
            {
                error = "Token endpoint rejected the request.",
                detail = JsonDocument.Parse(tokenBody).RootElement,
            });

        using var tokenDoc = JsonDocument.Parse(tokenBody);
        var root = tokenDoc.RootElement;
        var accessToken = root.GetProperty("access_token").GetString()!;

        Dictionary<string, object?>? claims = null;
        try
        {
            var jwt = new JwtSecurityToken(accessToken);
            claims = jwt.Claims.ToDictionary(c => c.Type, c => (object?)c.Value);
        }
        catch
        {
            // Opaque token — leave claims null.
        }

        return Ok(new
        {
            token_type = root.GetProperty("token_type").GetString(),
            expires_in = root.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : (int?)null,
            scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : null,
            claims,
        });
    }
}
