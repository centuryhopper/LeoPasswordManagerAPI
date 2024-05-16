using Business.DTOs;
using LeoPasswordManager.Models;
using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.DTOs;
using LeoPasswordManagerAPI.Models;

namespace LeoPasswordManagerAPI.Interfaces;

public interface IAccountRepository
{
    Task<UserDTO?> GetUserByIdAsDTOAsync(string userId);
    Task<UserDTO?> GetUserByEmailAsync(string email);
    Task<ServiceResponse> ChangePasswordAsync(string userId, string newPassword);
    Task<ServiceResponse> CheckPassword(string email, string password);
    Task<LoginResponse> LoginAsync(LoginDTO model);
    Task<ServiceResponse> LogoutAsync(string userId);
    Task<RegistrationResponse> RegisterAsync(RegisterDTO model);
    Task<PasswordmanagerUser?> GetUserByIdAsync(string UserId);
    Task<IEnumerable<RoleDTO>> GetRolesAsync();
    Task<ServiceResponse> UpdateUserAsync(EditAccountDTO model);
    Task<ServiceResponse> DeleteUserAsync(string Id);
    Task<ServiceResponse> ConfirmEmailAsync(AccountProviders accountProviders, string token, string userId);
    Task<EmailConfirmStatus> IsEmailConfirmed(string email);
}
