using AuthenticationService.Data.Interfaces;
using System.Security.Cryptography;

namespace AuthenticationService.Data.Implementations;

internal sealed record NewSaltProvider : INewSaltProvider
{
    private readonly byte[] _Salt;

    public NewSaltProvider()
    {
        _Salt = RandomNumberGenerator.GetBytes(16);
    }

    byte[] INewSaltProvider.Salt => _Salt;
}