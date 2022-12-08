namespace Application.Models.DTOs;

public class UserRegisterResult
{
    public UserRegisterResult(bool sucesso)
    {
        Sucesso = sucesso;
    }

    public bool Sucesso { get; private set; }
}