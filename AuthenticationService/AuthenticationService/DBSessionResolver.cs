using AuthenticationService.Data.Interfaces;
using Dapper;
using Microsoft.Data.SqlClient;
using StackExchange.Redis;

namespace AuthenticationService;

internal interface ISessionResolver
{
    Task<string> CreateSession(int userId);
    Task<List<string>> GetUserSessions(int userId);
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

    public Task<List<string>> GetUserSessions(int userId)
    {
        throw new NotImplementedException();
    }
}

internal sealed class RedisSessionResolver(IConnectionMultiplexer redis, INewSessionTokenProvider newSessionTokenProvider) : ISessionResolver
{
    public async Task<string> CreateSession(int userId)
    {
        var db = redis.GetDatabase();

        var sessionToken = Convert.ToBase64String(newSessionTokenProvider.Token);

        var key = $"session:{sessionToken}"; // session token stored as base 64 string
        await db.StringSetAsync(key, userId, TimeSpan.FromMinutes(1));

        await db.SetAddAsync($"user:{userId}:sessions", sessionToken);
        await db.KeyExpireAsync($"user:{userId}:sessions", TimeSpan.FromMinutes(1));

        return sessionToken;
    }

    public async Task<List<string>> GetUserSessions(int userId)
    {
        var db = redis.GetDatabase();

        var key = $"user:{userId}:sessions";
        var tokens = await db.SetMembersAsync(key);

        var active = new List<string>();

        foreach (var token in tokens)
        {
            if (!await db.KeyExistsAsync($"session:{token}"))
            {
                await db.SetRemoveAsync(key, token);
                continue;
            }

            if (token.IsNullOrEmpty)
                continue;

            active.Add((string)token!);
        }

        return active;
    }

}
