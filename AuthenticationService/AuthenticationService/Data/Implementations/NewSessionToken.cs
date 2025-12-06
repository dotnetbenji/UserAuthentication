using AuthenticationService.Data.Interfaces;
using System.Security.Cryptography;

namespace AuthenticationService.Data.Implementations;

internal sealed record NewSessionToken : INewSessionTokenProvider
{
    private readonly byte[] _Token;

    public NewSessionToken()
    {
        _Token = RandomNumberGenerator.GetBytes(64);
    }

    byte[] INewSessionTokenProvider.Token => _Token;
}