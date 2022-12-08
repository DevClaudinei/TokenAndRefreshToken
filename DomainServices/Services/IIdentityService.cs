using Application.Models.DTOs;
using System.Threading.Tasks;

namespace DomainServices.Services;

public interface IIdentityService
{
    Task<UserRegisterResult> RegisterUser(UserRegisterRequest userRegisterRequest);
    Task<UserLoginResult> Login(UserLoginRequest usuarioLogin);
}