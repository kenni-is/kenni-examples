using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KenniSampleApp.Controllers;

public class HomeController : Controller
{
    private readonly KenniOptions _kenni;

    public HomeController(IOptions<KenniOptions> kenni)
    {
        _kenni = kenni.Value;
    }

    public IActionResult Index()
    {
        ViewData["SignedIn"] = User.Identity?.IsAuthenticated ?? false;
        ViewData["Name"] = User.FindFirstValue("name") ?? User.FindFirstValue("sub");
        ViewData["NationalId"] = User.FindFirstValue("national_id");
        ViewData["ApiEnabled"] = _kenni.ApiEnabled;
        ViewData["M2MEnabled"] = _kenni.M2MEnabled;
        return View();
    }
}
