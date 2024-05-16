namespace LeoPasswordManagerAPI.Models;

public class AuthStatus
{
    public string Id { get; set; }
    public string? Name { get; set; }
    public string? Email { get; set; }
    public string? Role { get; set; }
    public bool Successful { get; set; }
    public string? Error { get; set; }

    public override string ToString()
    {
        return $"{nameof(Id)}:{Id}, {nameof(Name)}:{Name}, {nameof(Email)}:{Email}, {nameof(Role)}:{Role}, {nameof(Successful)}:{Successful}, {nameof(Error)}:{Error}, ";
    }
}
