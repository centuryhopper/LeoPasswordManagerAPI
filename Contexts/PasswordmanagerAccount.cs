using System;
using System.Collections.Generic;

namespace LeoPasswordManagerAPI.Contexts;

public partial class PasswordmanagerAccount
{
    public string Id { get; set; } = null!;

    public string Userid { get; set; } = null!;

    public string Title { get; set; } = null!;

    public string Username { get; set; } = null!;

    public string Password { get; set; } = null!;

    public string? CreatedAt { get; set; }

    public string? LastUpdatedAt { get; set; }
}
