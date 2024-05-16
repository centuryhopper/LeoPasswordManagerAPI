using System.ComponentModel.DataAnnotations;
namespace LeoPasswordManagerAPI.Models;

public class UserRoleDTO
{
    public string UserId { get; set; }
    public string RoleId { get; set; }
    public string RoleName { get; set; }
}
