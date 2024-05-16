namespace LeoPasswordManagerAPI.Models;

public class PasswordAccountModel
{
    public string Id { get; set; }
    public string Title { get; set; }
    public string UserName { get; set; }
    public string Password { get; set; }
    public string UserId { get; set; }

    public override string ToString()
    {
        return $"{nameof(Id)}:{Id}, {nameof(Title)}:{Title}, {nameof(UserName)}:{UserName}, {nameof(Password)}:{Password}, {nameof(UserId)}:{UserId}";
    }
}