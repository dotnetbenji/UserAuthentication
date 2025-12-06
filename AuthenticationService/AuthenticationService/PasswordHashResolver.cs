using System.Security.Cryptography;
using System.Text;

namespace AuthenticationService;

internal interface IPasswordHashResolver
{
    byte[] Resolve(string password, byte[] salt);
}

internal sealed class PasswordHashResolver : IPasswordHashResolver
{
    private const int iterations = 100_000;
    private const int byteHashLength = 32;

    public byte[] Resolve(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            byteHashLength
        );
    }
}
