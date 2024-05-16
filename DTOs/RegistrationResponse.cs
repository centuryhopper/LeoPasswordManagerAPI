
namespace LeoPasswordManagerAPI.DTOs;

public record RegistrationResponse(bool flag, string msg = null!, string Id = null!, string Name = null!, string Role = null!, string Email = null!);
