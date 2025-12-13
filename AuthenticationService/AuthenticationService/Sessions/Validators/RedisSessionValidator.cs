using StackExchange.Redis;

namespace AuthenticationService.Sessions.Validators;

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
