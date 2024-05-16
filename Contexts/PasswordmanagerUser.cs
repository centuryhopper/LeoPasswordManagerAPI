using System;
using System.Collections;
using System.Collections.Generic;

namespace LeoPasswordManagerAPI.Contexts;

public partial class PasswordmanagerUser
{
    public string Id { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string Passwordhash { get; set; } = null!;

    public string Salt { get; set; } = null!;

    public string Firstname { get; set; } = null!;

    public string Lastname { get; set; } = null!;

    public BitArray Emailconfirmed { get; set; } = null!;

    public BitArray Lockoutenabled { get; set; } = null!;

    public DateOnly? Lockoutenddateutc { get; set; }

    public int Accessfailedcount { get; set; }

    public DateTime? Datelastlogin { get; set; }

    public DateTime? Datelastlogout { get; set; }

    public DateTime? Datecreated { get; set; }

    public DateTime? Dateretired { get; set; }

    public string? Newemail { get; set; }

    public virtual ICollection<Userrole> Userroles { get; set; } = new List<Userrole>();

    public virtual ICollection<Usertoken> Usertokens { get; set; } = new List<Usertoken>();
}
