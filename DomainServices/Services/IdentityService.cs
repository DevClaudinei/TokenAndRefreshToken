using Application.Models.DTOs;
using Identity.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace DomainServices.Services;

public class IdentityService : IIdentityService
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtOptions _jwtOptions;

    public IdentityService(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IOptions<JwtOptions> jwtOptions)
    {
        if (jwtOptions is null)
        {
            throw new ArgumentNullException(nameof(jwtOptions));
        }
        _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _jwtOptions = jwtOptions.Value;

    }

    public async Task<UserRegisterResult> RegisterUser(UserRegisterRequest userRegisterRequest)
    {
        var identityUser = new IdentityUser
        {
            UserName = userRegisterRequest.Email,
            Email = userRegisterRequest.Email,
            EmailConfirmed = true
        };

        var registerUser = await _userManager.CreateAsync(identityUser, userRegisterRequest.Password);

        if (registerUser.Succeeded) await _userManager.SetLockoutEnabledAsync(identityUser, false);

        var usuarioResult = new UserRegisterResult(registerUser.Succeeded);

        return usuarioResult;
    }

    public async Task<UserLoginResult> Login(UserLoginRequest userLoginRequest)
    {
        var userFound = await _signInManager.PasswordSignInAsync(userLoginRequest.Email, userLoginRequest.Senha, false, true);

        //if (userFound.Succeeded) /*return await GenerateCredentials(userLoginRequest.Email);*/
        if (!userFound.Succeeded)
        {
            if (userFound.IsLockedOut) throw new ArgumentException("Essa conta está bloqueada");

            if (userFound.IsNotAllowed) throw new ArgumentException("Essa conta não tem permissão para fazer login");

            if (userFound.RequiresTwoFactor) throw new ArgumentException("É necessário confirmar o login no seu segundo fator de autenticação");

            throw new ArgumentException("Usuário ou senha estão incorretos");
        }

        var userCredentials = await GenerateCredentials(userLoginRequest.Email);
        var loginResponse = new UserLoginResult(userCredentials.AccessToken, userCredentials.RefreshToken);

        return loginResponse;
    }

    private async Task<UserLoginResult> GenerateCredentials(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        var accessTokenClaims = await GetClaims(user, addUserClaims: true);
        var refreshTokenClaims = await GetClaims(user, addUserClaims: false);

        var tokenExpiration = DateTime.Now.AddSeconds(_jwtOptions.AccessTokenExpiration);
        var refreshTokenEpiration = DateTime.Now.AddSeconds(_jwtOptions.RefreshTokenExpiration);

        var accessToken = GenerateToken(accessTokenClaims, tokenExpiration);
        var refreshToken = GenerateToken(refreshTokenClaims, refreshTokenEpiration);

        return new UserLoginResult
        (
            accessToken: accessToken,
            refreshToken: refreshToken
        );
    }

    private string GenerateToken(IEnumerable<Claim> claims, DateTime tokenExpiration)
    {
        var jwt = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: DateTime.Now,
            expires: tokenExpiration,
            signingCredentials: _jwtOptions.SigningCredentials);

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private async Task<IList<Claim>> GetClaims(IdentityUser identityUser, bool addUserClaims)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, identityUser.Id),
            new Claim(JwtRegisteredClaimNames.Email, identityUser.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Nbf, DateTime.Now.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToString())
        };

        if (addUserClaims)
        {
            var userClaims = await _userManager.GetClaimsAsync(identityUser);
            var roles = await _userManager.GetRolesAsync(identityUser);

            claims.AddRange(userClaims);

            foreach (var role in roles) claims.Add(new Claim("role", role));
        }

        return claims;
    }
}