using System;
using System.Collections.Generic;

namespace LeoPasswordManagerAPI.DTOs;

public partial class PasswordUploadDTO
{

    public string? Title { get; set; } = null!;

    public string? Username { get; set; } = null!;

    public string? Password { get; set; } = null!;
}
