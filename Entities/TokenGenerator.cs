using System;
using System.Security.Cryptography;
using System.Text;

namespace LeoPasswordManagerAPI.Models;

public static class TokenGenerator
{
    public static string GenerateToken(int length)
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            var bytes = new byte[length];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
