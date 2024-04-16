using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace KenniSampleApp.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize(AuthenticationSchemes = "bearer")]
public class AuthedController : ControllerBase
{

  [HttpGet, Route("")]
  public string Test()
  {
    return "Success! You're accessing an authenticated resource.";
  }
}
