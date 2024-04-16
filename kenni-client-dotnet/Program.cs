using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services
  .AddAuthentication(options =>
  {
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
  })
  .AddCookie()
  .AddOpenIdConnect("oidc", options =>
  {
    options.Authority = builder.Configuration["Kenni:Authority"];
    options.ClientId = builder.Configuration["Kenni:ClientId"];
    options.ClientSecret = builder.Configuration["Kenni:ClientSecret"];
    options.ResponseType = "code";

    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("national_id");

    var apiScope = builder.Configuration["Kenni:ApiScope"];
    if (apiScope != null)
    {
      options.Scope.Add(apiScope);
    }

    options.SaveTokens = true;
  })
  .AddJwtBearer("bearer", options =>
  {
    options.Authority = builder.Configuration["Kenni:Authority"];
    options.TokenValidationParameters = new TokenValidationParameters
    {

      ValidIssuer = builder.Configuration["Kenni:Authority"],
      ValidAudience = $"{builder.Configuration["Kenni:ClientId"]}-api",
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = false,
      ValidateIssuerSigningKey = true,
    };
  });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
  app.UseExceptionHandler("/Home/Error");
  // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
  app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
  name: "default",
  pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
