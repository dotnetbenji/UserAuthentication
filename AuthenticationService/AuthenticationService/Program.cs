using AuthenticationService;
using AuthenticationService.Data.Implementations;
using AuthenticationService.Data.Interfaces;
using Dapper;
using Microsoft.Data.SqlClient;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    string? redisConnectionString = builder.Configuration.GetSection("Redis:ConnectionString").Value;
    if (redisConnectionString is null)
        throw new Exception("Redis connection string not found in config");

    return ConnectionMultiplexer.Connect(redisConnectionString);
});
builder.Services.AddTransient<INewSessionTokenProvider, NewSessionToken>();
builder.Services.AddTransient<INewSaltProvider, NewSaltProvider>();
builder.Services.AddTransient<ISessionValidator, RedisSessionValidator>();
builder.Services.AddTransient<IPasswordHashResolver, PasswordHashResolver>();
builder.Services.AddTransient<ISessionResolver, RedisSessionResolver>();

builder.Services.AddScoped<SqlConnection>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var conn = new SqlConnection(config.GetConnectionString("DefaultConnection"));
    conn.Open();
    return conn;
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapPost("/create/user", async (CreateUserRequest request, SqlConnection db, IPasswordHashResolver passwordHashResolver, INewSaltProvider newSalt) =>
{
    var existingUsername = await db.QuerySingleOrDefaultAsync<string>(
        "SELECT UserId FROM Users WHERE Username = @Username",
        new { Username = request.Username }
    );

    if (existingUsername != null)
        return Results.Conflict("Username not available");

    var passwordHash = passwordHashResolver.Resolve(request.Password, newSalt.Salt);

    string? username;
    try
    {
        username = await db.QuerySingleAsync<string>(
            @"INSERT INTO Users (Username, PasswordHash, PasswordSalt, UserCreated)
              OUTPUT INSERTED.Username
              VALUES (@Username, @PasswordHash, @PasswordSalt, @CreationDate)",
            new { Username = request.Username, PasswordHash = passwordHash, PasswordSalt = newSalt.Salt, CreationDate = DateTime.UtcNow }
        );
    }
    catch (SqlException exception)
    {
        if(exception.IsUniqueConstraintViolation())
            return Results.Conflict("Username already exists");

        return Results.Problem("Failed to create user");
    }

    return Results.Ok(new { Username = username });
});

app.MapPost("/login", async (
    LoginRequest request, 
    SqlConnection db, 
    IPasswordHashResolver passwordHashResolver, 
    ISessionResolver sessionResolver) =>
{
    byte[]? salt = await db.QuerySingleOrDefaultAsync<byte[]>("SELECT PasswordSalt FROM Users WHERE Username = @Username", new { Username = request.Username });

    if (salt is null)
    {
        return Results.Problem("User not found");
    }

    var passwordHash = passwordHashResolver.Resolve(request.Password, salt);

    var user = await db.QuerySingleOrDefaultAsync<User>(
        "SELECT UserId, Username FROM Users WHERE Username = @Username AND PasswordHash = @PasswordHash",
        new { request.Username, PasswordHash = passwordHash });

    if (user == null)
        return Results.Unauthorized();

    string encodedSessionToken = await sessionResolver.CreateSession(user.UserId);

    return Results.Ok(new
    {
        SessionToken = encodedSessionToken,
        TokenType = "Bearer"
    });
});

app.MapGet("/info", async (
    HttpContext ctx, 
    ISessionValidator sessionValidator,
    ISessionResolver sessionResolver) =>
{
    var tokenString = GetSessionTokenFromRequest(ctx);
    if (tokenString == null)
        return Results.Unauthorized();

    int? userId = await sessionValidator.Validate(new SessionToken(tokenString));
    if (userId is null)
        return Results.Unauthorized();

    var sessions = await sessionResolver.GetUserSessions((int)userId);

    return Results.Ok(new { 
        Sessions = sessions
    });
});

app.Run();

static string? GetSessionTokenFromRequest(HttpContext ctx)
{
    var header = ctx.Request.Headers.Authorization.ToString();

    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        return null;

    string encoded = header["Bearer ".Length..].Trim();

    try
    {
        return encoded;
    }
    catch
    {
        return null;
    }
}

internal static class SqlExceptionExtensions
{
    public static bool IsUniqueConstraintViolation(this SqlException exception)
        => exception.Number == 2627 || exception.Number == 2601;
}

internal sealed record User(int UserId, string Username);

internal sealed record LoginRequest(string Username, string Password);
internal sealed record CreateUserRequest(string Username, string Password);