using AuthenticationService.Data.Interfaces;
using System.Security.Cryptography;

namespace AuthenticationService.Data.Implementations;

internal sealed record NewSessionToken : INewSessionTokenProvider
{
    private readonly string _Token;

    public NewSessionToken()
    {
        _Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }

    string INewSessionTokenProvider.Token => _Token;
}