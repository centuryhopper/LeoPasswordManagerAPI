using System.ComponentModel.DataAnnotations;
using System.Configuration;
namespace LeoPasswordManagerAPI.Models;



public class RegisterDTO
{
    [Required(ErrorMessage = "Please enter a valid email address."), EmailAddress]
    public string Email { get; set; }
    [Required(ErrorMessage = "Password is required.")]
    [MinLength(6, ErrorMessage = "Password must be at least 6 characters long.")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{6,}$",
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
    public string Password { get; set; }
    [Compare(nameof(Password), ErrorMessage = "Confirm password doesn't match, Please try again!")]
    public string ConfirmPassword { get; set; }
    [Display(Name = "First Name")]
    public string FirstName { get; set; }
    [Display(Name = "Last Name")]
    public string LastName { get; set; }
    public string? Role { get; set; }
}
