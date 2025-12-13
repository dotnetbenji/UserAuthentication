using AuthenticationService.Data.Interfaces;
using Dapper;
using Microsoft.Data.SqlClient;

namespace AuthenticationService.Sessions.Resolvers;

internal sealed class DBSessionResolver(SqlConnection db, INewSessionTokenProvider newSessionTokenProvider) : ISessionResolver
{
    public async Task<string> CreateSession(User user)
    {
        await db.ExecuteAsync(
            "INSERT INTO Sessions (UserId, Token, ExpiresAt) VALUES (@UserId, @Token, @ExpiresAt)",
            new { UserId = user.UserId, Token = newSessionTokenProvider.Token, ExpiresAt = DateTime.UtcNow.AddMinutes(1) }
        );

        return Convert.ToBase64String(newSessionTokenProvider.Token);
    }

    public Task<List<string>> GetUserSessions(int userId)
    {
        throw new NotImplementedException();
    }
}
