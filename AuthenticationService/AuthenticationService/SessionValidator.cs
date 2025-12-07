using Dapper;
using Microsoft.Data.SqlClient;
using StackExchange.Redis;

namespace AuthenticationService;

internal sealed record SessionToken(string Token);
internal interface ISessionValidator
{
    Task<int?> Validate(SessionToken token);
}

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

internal sealed class RedisSessionValidator(IConnectionMultiplexer redis) : ISessionValidator
{
    public async Task<int?> Validate(SessionToken token)
    {
        var db = redis.GetDatabase();
        var key = $"session:{token.Token}";
        var ttl = TimeSpan.FromMinutes(1);

        RedisValue userId = await db.StringGetAsync(key);
        if (userId.IsNullOrEmpty)
            return null;

        var userSessionsKey = $"user:{userId}:sessions";

        bool extended = await db.KeyExpireAsync(key, ttl);
        bool extendedSessionsKey = await db.KeyExpireAsync(userSessionsKey, ttl);

        if (!extended)
            return null;

        return (int)userId;
    }
}

internal sealed record Session(int UserId, DateTime ExpiresAt);
