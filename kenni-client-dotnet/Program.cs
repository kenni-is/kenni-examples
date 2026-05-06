using System.IdentityModel.Tokens.Jwt;
using DotNetEnv;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

// Load `.env` (if present). Real env vars still win.
Env.TraversePath().Load();

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

string Required(string key) =>
    config[key] ?? throw new InvalidOperationException($"Missing required env var: {key}");

var issuer = Required("KENNI_ISSUER");
var clientId = Required("KENNI_CLIENT_ID");
var clientSecret = Required("KENNI_CLIENT_SECRET");
var apiScope = config["KENNI_API_SCOPE"];
var apiAudience = config["KENNI_API_AUDIENCE"] ?? $"{clientId}-api";
var m2mClientId = config["KENNI_M2M_CLIENT_ID"];
var m2mClientSecret = config["KENNI_M2M_CLIENT_SECRET"];
var m2mScope = config["KENNI_M2M_SCOPE"];

var apiEnabled = !string.IsNullOrEmpty(apiScope);
var m2mEnabled =
    !string.IsNullOrEmpty(m2mClientId)
    && !string.IsNullOrEmpty(m2mClientSecret)
    && !string.IsNullOrEmpty(m2mScope);

builder.Services.Configure<KenniOptions>(o =>
{
    o.Issuer = issuer;
    o.ClientId = clientId;
    o.ClientSecret = clientSecret;
    o.ApiScope = apiScope;
    o.ApiAudience = apiAudience;
    o.M2MClientId = m2mClientId;
    o.M2MClientSecret = m2mClientSecret;
    o.M2MScope = m2mScope;
    o.ApiEnabled = apiEnabled;
    o.M2MEnabled = m2mEnabled;
});

builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient();

// Don't strip OIDC claim names — keep `sub`, `name`, `national_id`, etc. as-is
// instead of remapping to the long ClaimTypes.* URIs.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

var auth = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = issuer;
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;
        options.ResponseType = "code";
        options.UsePkce = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = false;
        options.MapInboundClaims = false;
        options.SignedOutRedirectUri = "/";
        options.SignedOutCallbackPath = "/signout-callback-oidc";

        // OIDC enforces HTTPS on the authority by default. That's the right
        // default for prod, but it blocks dev-time http issuers (e.g. a local
        // mock IdP, or a tunnel that terminates TLS upstream). Allow http
        // only in Development.
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("national_id");
        options.Scope.Add("offline_access");
        if (apiEnabled) options.Scope.Add(apiScope!);

        options.TokenValidationParameters.NameClaimType = "name";
    });

auth.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.Authority = issuer;
    options.MapInboundClaims = false;
    // Same dev-vs-prod treatment as the OIDC handler above.
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = issuer,
        ValidAudience = apiAudience,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        NameClaimType = "name",
    };
});

builder.Services.AddAuthorization(options =>
{
    // Always register the policy so [Authorize(Policy = "ApiScope")] resolves.
    // If KENNI_API_SCOPE is not configured the policy denies — the
    // /api/protected-resource endpoint then always returns 403.
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AuthenticationSchemes = new[] { JwtBearerDefaults.AuthenticationScheme };
        policy.RequireAssertion(ctx =>
        {
            if (string.IsNullOrEmpty(apiScope)) return false;
            var scope = ctx.User.FindFirst("scope")?.Value ?? "";
            return scope.Split(' ').Contains(apiScope);
        });
    });
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");

app.Run();

public sealed class KenniOptions
{
    public string Issuer { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string? ApiScope { get; set; }
    public string ApiAudience { get; set; } = "";
    public string? M2MClientId { get; set; }
    public string? M2MClientSecret { get; set; }
    public string? M2MScope { get; set; }
    public bool ApiEnabled { get; set; }
    public bool M2MEnabled { get; set; }
}
