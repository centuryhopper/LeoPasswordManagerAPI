

namespace LeoPasswordManagerAPI.Models;

public class AccessToken
{
    public string cachedAt { get; set; }
    public string clientId { get; set; }
    public string credentialType { get; set; }
    public string environment { get; set; }
    public string expiresOn { get; set; }
    public string extendedExpiresOn { get; set; }
    public string homeAccountId { get; set; }
    public string realm { get; set; }
    public string secret { get; set; }
    public string target { get; set; }
    public string tokenType { get; set; }
}