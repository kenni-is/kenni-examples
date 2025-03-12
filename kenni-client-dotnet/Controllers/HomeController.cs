using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace KenniSampleApp.Controllers;

public class HomeController : Controller
{
  private readonly ILogger<HomeController> _logger;

  public HomeController(ILogger<HomeController> logger)
  {
    _logger = logger;
  }

  public IActionResult Index()
  {
    return View();
  }

  [Authorize(AuthenticationSchemes = "oidc")]
  public async Task<IActionResult> LoggedIn()
  {
    ViewData["NationalID"] = User.FindFirstValue("national_id");
    ViewData["Name"] = User.FindFirstValue("name");

    var token = await HttpContext.GetTokenAsync("oidc", "access_token");
    ViewData["AccessToken"] = token;

    return View();
  }

  [Authorize(AuthenticationSchemes = "oidc")]
  public async Task<IActionResult> Logout()
  {
    // Only sign out locally from ASP.NET Core authentication scheme
    await HttpContext.SignOutAsync();
    return Redirect("/");
  }

  [Authorize(AuthenticationSchemes = "oidc")]
  public async Task<IActionResult> RpLogout()
  {
    // End the local session
    await HttpContext.SignOutAsync();

    // Sign out from Kenni
    return SignOut("oidc");
  }
}
