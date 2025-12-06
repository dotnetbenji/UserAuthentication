using AuthenticationService;
using AuthenticationService.Data.Implementations;
using AuthenticationService.Data.Interfaces;
using Dapper;
using Microsoft.Data.SqlClient;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddTransient<INewSessionTokenProvider, NewSessionToken>();
builder.Services.AddTransient<INewSaltProvider, NewSaltProvider>();
builder.Services.AddTransient<ISessionValidator, SessionValidator>();

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

app.MapPost("/create/user", async (CreateUserRequest request, SqlConnection db, INewSaltProvider newSalt) =>
{
    var existingUsername = await db.QuerySingleOrDefaultAsync<string>(
        "SELECT UserId FROM Users WHERE Username = @Username",
        new { Username = request.Username }
    );

    if (existingUsername != null)
        return Results.Conflict("Username not available");

    int iterations = 100_000;
    int byteHashLength = 32;

    byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(request.Password),
        newSalt.Salt,
        iterations,
        HashAlgorithmName.SHA512,
        byteHashLength
    );

    string? username;
    try
    {
        username = await db.QuerySingleAsync<string>(
            @"INSERT INTO Users (Username, PasswordHash, PasswordSalt, UserCreated)
              OUTPUT INSERTED.Username
              VALUES (@Username, @PasswordHash, @PasswordSalt, @CreationDate)",
            new { Username = request.Username, PasswordHash = hash, PasswordSalt = newSalt.Salt, CreationDate = DateTime.UtcNow }
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

app.MapPost("/login", async (LoginRequest request, SqlConnection db, INewSessionTokenProvider newSessionTokenProvider) =>
{
    byte[]? salt = await db.QuerySingleOrDefaultAsync<byte[]>("SELECT PasswordSalt FROM Users WHERE Username = @Username", new { Username = request.Username });

    if (salt is null)
    {
        return Results.Problem("User not found");
    }

    int iterations = 100_000;
    int byteHashLength = 32;

    byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(request.Password),
        salt,
        iterations,
        HashAlgorithmName.SHA512,
        byteHashLength
    );

    var user = await db.QuerySingleOrDefaultAsync<User>(
        "SELECT UserId, Username FROM Users WHERE Username = @Username AND PasswordHash = @PasswordHash",
        new { request.Username, PasswordHash = hash });

    if (user == null)
        return Results.Unauthorized();

    await db.ExecuteAsync(
        "INSERT INTO Sessions (UserId, Token, ExpiresAt) VALUES (@UserId, @Token, @ExpiresAt)",
        new { UserId = user.UserId, Token = newSessionTokenProvider.Token, ExpiresAt = DateTime.UtcNow.AddMinutes(1) }
    );

    string encodedToken = Convert.ToBase64String(newSessionTokenProvider.Token);
    return Results.Ok(new
    {
        SessionToken = encodedToken,
        TokenType = "Bearer"
    });
});

app.MapGet("/info", async (HttpContext ctx, ISessionValidator validator) =>
{
    var tokenBytes = GetSessionTokenFromRequest(ctx);
    if (tokenBytes == null)
        return Results.Unauthorized();

    int? userId = await validator.Validate(new SessionToken(tokenBytes));
    if (userId is null)
        return Results.Unauthorized();

    return Results.Ok(userId);
});

app.Run();

static byte[]? GetSessionTokenFromRequest(HttpContext ctx)
{
    var header = ctx.Request.Headers.Authorization.ToString();

    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        return null;

    string encoded = header["Bearer ".Length..].Trim();

    try
    {
        return Convert.FromBase64String(encoded);
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