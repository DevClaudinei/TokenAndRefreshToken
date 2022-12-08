using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace example_dotnet_identity.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    [HttpGet]
    [Route("test-auth")]
    [Authorize]
    public IActionResult GetTest()
    {
        return Ok("Only authenticated user can consume this endpoint");
    }
}