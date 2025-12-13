using AuthenticationService.Data.Interfaces;
using StackExchange.Redis;
using System.Text.Json;

namespace AuthenticationService.Sessions.Resolvers;

internal sealed class RedisSessionResolver(IConnectionMultiplexer redis, INewSessionTokenProvider newSessionTokenProvider) : ISessionResolver
{
    public async Task<string> CreateSession(User user)
    {
        var db = redis.GetDatabase();

        var sessionToken = Convert.ToBase64String(newSessionTokenProvider.Token);

        var key = $"session:{sessionToken}"; // session token stored as base 64 string
        var value = JsonSerializer.Serialize(user);
        await db.StringSetAsync(key, value, TimeSpan.FromMinutes(1));

        await db.SetAddAsync($"user:{user.UserId}:sessions", sessionToken);
        await db.KeyExpireAsync($"user:{user.UserId}:sessions", TimeSpan.FromMinutes(1));

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