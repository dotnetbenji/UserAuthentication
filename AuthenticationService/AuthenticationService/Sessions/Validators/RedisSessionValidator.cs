using StackExchange.Redis;
using System.Text.Json;

namespace AuthenticationService.Sessions.Validators;

internal sealed class RedisSessionValidator(IConnectionMultiplexer redis) : ISessionValidator
{
    public async Task<User?> Validate(SessionToken token)
    {
        var db = redis.GetDatabase();
        var key = $"session:{token.Token}";
        var ttl = TimeSpan.FromMinutes(1);

        RedisValue redisUser = await db.StringGetAsync(key);
        if (redisUser.IsNullOrEmpty)
            return null;

        User? user = JsonSerializer.Deserialize<User>((string)redisUser!);
        if(user == null) 
            return null;

        var userSessionsKey = $"user:{user.UserId}:sessions";

        bool extended = await db.KeyExpireAsync(key, ttl);
        bool extendedSessionsKey = await db.KeyExpireAsync(userSessionsKey, ttl);

        if (!extended)
            return null;

        return user;
    }
}
