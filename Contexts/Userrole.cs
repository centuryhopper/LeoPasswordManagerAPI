using System;
using System.Collections.Generic;

namespace LeoPasswordManagerAPI.Contexts;

public partial class Userrole
{
    public string Id { get; set; } = null!;

    public string? Userid { get; set; }

    public string? Roleid { get; set; }

    public virtual Role? Role { get; set; }

    public virtual PasswordmanagerUser? User { get; set; }
}
