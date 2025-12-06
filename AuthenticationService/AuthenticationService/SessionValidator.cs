using Dapper;
using Microsoft.Data.SqlClient;

namespace AuthenticationService;

internal sealed record SessionToken(byte[] Token);
internal interface ISessionValidator
{
    Task<int?> Validate(SessionToken token);
}

internal sealed class SessionValidator(SqlConnection _db) : ISessionValidator
{
    public async Task<int?> Validate(SessionToken token)
    {
        var session = await _db.QuerySingleOrDefaultAsync<Session>(
            "SELECT UserId, ExpiresAt FROM Sessions WHERE Token = @Token",
            new { Token = token.Token }
        );

        if (session == default)
            return null;

        if (session.ExpiresAt < DateTime.UtcNow)
            return null;

        return session.UserId;
    }
}

internal sealed record Session(int UserId, DateTime ExpiresAt);
