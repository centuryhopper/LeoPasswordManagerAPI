using System.ComponentModel.DataAnnotations;
namespace LeoPasswordManagerAPI.Models;

public class UserModel
{
    public string Id { get; set; }
    public string Salt { get; set; }
    public string PasswordHash { get; set; }
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Role { get; set; }

    public override string ToString()
    {
        return $"{nameof(Id)}:{Id}, {nameof(Salt)}:{Salt}, {nameof(PasswordHash)}:{PasswordHash}, {nameof(Email)}:{Email}, {nameof(FirstName)}:{FirstName}, {nameof(LastName)}:{LastName}, {nameof(Role)}:{Role}";
    }
}
