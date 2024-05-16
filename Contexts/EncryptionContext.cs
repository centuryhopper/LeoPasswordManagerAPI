

using System.Security.Cryptography;
using System.Text;

namespace LeoPasswordManagerAPI.Contexts;


/// <summary>
/// Hashing is a one-way process that converts a password to ciphertext using hash algorithms. A hashed password cannot be decrypted, but a hacker can try to reverse engineer it. Password salting adds random characters before or after a password prior to hashing to obfuscate the actual password.
/// Source: https://www.pingidentity.com/en/resources/blog/post/encryption-vs-hashing-vs-salting.html
/// </summary>
public class EncryptionContext
{
    /*
    Hash(PasswordEntered + Salt)  = hash in database = authenticated
    Hash(PasswordEntered + Salt)  <> hash in database = not authenticated
    https://stackoverflow.com/questions/41381333/asp-net-identity-where-is-the-salt-stored
    */
    private readonly IConfiguration configuration;
    private readonly IHostEnvironment env;
    byte[] Key, IV;
    private ICryptoTransform EncryptorTransform, DecryptorTransform;
    private System.Text.UTF8Encoding UTFEncoder;
    AesManaged enc = new AesManaged();


    public EncryptionContext(IConfiguration configuration, IHostEnvironment env)
    {
        this.configuration = configuration;
        this.env = env;
        string _encKey = env.IsDevelopment() ? configuration.GetConnectionString("EncryptionKey")! : Environment.GetEnvironmentVariable("EncryptionKey");

        string _initVector = env.IsDevelopment() ? configuration.GetConnectionString("InitVector")! : Environment.GetEnvironmentVariable("InitVector");

        // byte[] key = new byte[16]; // 16 bytes for AES-128, change to 32 bytes for AES-256
        // byte[] iv = new byte[16]; // 16 bytes for AES

        // using (var rng = RandomNumberGenerator.Create())
        // {
        //     rng.GetBytes(key);
        //     rng.GetBytes(iv);
        // }

        // string base64Key = Convert.ToBase64String(key);
        // string base64IV = Convert.ToBase64String(iv);

        // Console.WriteLine("AES Key (Base64): " + base64Key);
        // Console.WriteLine("IV (Base64): " + base64IV);

        enc.Key = Convert.FromBase64String(_encKey);
        enc.IV = Convert.FromBase64String(_initVector);

        EncryptorTransform = enc.CreateEncryptor(enc.Key, enc.IV);
        DecryptorTransform = enc.CreateDecryptor(enc.Key, enc.IV);

        UTFEncoder = new System.Text.UTF8Encoding();
    }



    public byte[] Encrypt(string TextValue)
    {
        byte[] bytes = UTFEncoder.GetBytes(TextValue);
        MemoryStream memoryStream = new MemoryStream();

        // Write the decrypted value to the encryption stream
        CryptoStream cryptoStream = new CryptoStream(memoryStream, EncryptorTransform, CryptoStreamMode.Write);
        cryptoStream.Write(bytes, 0, bytes.Length);
        cryptoStream.FlushFinalBlock();

        // Read encrypted value back out of the stream
        memoryStream.Position = 0;
        byte[] encrypted = new byte[memoryStream.Length];
        memoryStream.Read(encrypted, 0, encrypted.Length);

        cryptoStream.Close();
        memoryStream.Close();

        return encrypted;
    }

    public string Decrypt(byte[] EncryptedValue)
    {
        // Write the encrypted value to the decryption stream
        MemoryStream encryptedStream = new MemoryStream();
        CryptoStream decryptStream = new CryptoStream(encryptedStream, DecryptorTransform, CryptoStreamMode.Write);
        decryptStream.Write(EncryptedValue, 0, EncryptedValue.Length);
        decryptStream.FlushFinalBlock();

        // Read the decrypted value from the stream
        encryptedStream.Position = 0;
        byte[] decryptedBytes = new byte[encryptedStream.Length];
        encryptedStream.Read(decryptedBytes, 0, decryptedBytes.Length);
        encryptedStream.Close();

        return UTFEncoder.GetString(decryptedBytes);

    }

    public string OneWayHash(string Password)
    {
        using var sha = SHA256.Create();
        var asBytes = Encoding.Default.GetBytes(Password);
        var hashed = sha.ComputeHash(asBytes);
        return Convert.ToBase64String(hashed);
    }
}