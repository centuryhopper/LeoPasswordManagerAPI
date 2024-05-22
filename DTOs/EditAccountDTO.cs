using System.ComponentModel.DataAnnotations;
namespace LeoPasswordManagerUI.Models;

public class EditAccountDTO
{
    public string? Id { get; set; }
    public string? Email { get; set; }
    public string? OldPassword { get; set; }

    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{6,}$|^$",
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character."), Required(ErrorMessage = "Please enter a value")]
    public string NewPassword { get; set; } = null!;

    [Compare(nameof(NewPassword), ErrorMessage = "The password and confirmation password do not match."), Required(ErrorMessage = "Please enter a value")]
    public string ConfirmNewPassword { get; set; } = null!;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Role { get; set; }

    public override string ToString()
    {
        return $"{nameof(Email)}:{Email}, {nameof(OldPassword)}:{OldPassword}, ";
    }
}
