using System;
using System.Collections.Generic;

namespace LeoPasswordManagerAPI.Contexts;

public partial class Usertoken
{
    public string Id { get; set; } = null!;

    public string Loginprovider { get; set; } = null!;

    public string Providerkey { get; set; } = null!;

    public string? Userid { get; set; }

    public virtual PasswordmanagerUser? User { get; set; }
}
