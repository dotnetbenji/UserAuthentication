using AuthenticationService.Data.Interfaces;
using Dapper;
using Microsoft.Data.SqlClient;

namespace AuthenticationService;

internal interface ISessionResolver
{
    Task<string> CreateSession(int userId);
}

internal sealed class DBSessionResolver(SqlConnection db, INewSessionTokenProvider newSessionTokenProvider) : ISessionResolver
{
    public async Task<string> CreateSession(int userId)
    {
        await db.ExecuteAsync(
            "INSERT INTO Sessions (UserId, Token, ExpiresAt) VALUES (@UserId, @Token, @ExpiresAt)",
            new { UserId = userId, Token = newSessionTokenProvider.Token, ExpiresAt = DateTime.UtcNow.AddMinutes(1) }
        );

        return Convert.ToBase64String(newSessionTokenProvider.Token);
    }
}
