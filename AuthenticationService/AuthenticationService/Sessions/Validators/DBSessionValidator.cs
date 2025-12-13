using Dapper;
using Microsoft.Data.SqlClient;

namespace AuthenticationService.Sessions.Validators;

internal sealed record SessionToken(string Token);

internal sealed class DBSessionValidator(SqlConnection _db) : ISessionValidator
{
    public async Task<int?> Validate(SessionToken token)
    {
        byte[] tokenBytes = Convert.FromBase64String(token.Token); // convert to bytes for db check

        var session = await _db.QuerySingleOrDefaultAsync<Session>(
            "SELECT UserId, ExpiresAt FROM Sessions WHERE Token = @Token",
            new { Token = tokenBytes }
        );

        if (session == default)
            return null;

        if (session.ExpiresAt < DateTime.UtcNow)
            return null;

        return session.UserId;
    }
}

internal sealed record Session(int UserId, DateTime ExpiresAt);
