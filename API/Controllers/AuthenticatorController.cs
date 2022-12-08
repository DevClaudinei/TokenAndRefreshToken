using Application.Models.DTOs;
using DomainServices.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace example_dotnet_identity.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticatorController : ControllerBase
{
    private readonly IIdentityService _identityService;

    public AuthenticatorController(IIdentityService identityService)
    {
        _identityService = identityService ?? throw new ArgumentNullException(nameof(identityService));
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> CreateUserAsync(UserRegisterRequest userRegisterRequest)
    {
        var resultado = await _identityService.RegisterUser(userRegisterRequest);

        return Created("Id:", resultado);
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> LoginAsync(UserLoginRequest userLoginRequest)
    {
        try
        {
            var resultado = await _identityService.Login(userLoginRequest);
            return Ok(resultado);
        }
        catch(Exception ex)
        {
            return Unauthorized(ex.Message);
        }

    }
}