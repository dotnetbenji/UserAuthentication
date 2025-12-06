using AuthenticationService.Data.Implementations;
using AuthenticationService.Data.Interfaces;
using Dapper;
using Microsoft.Data.SqlClient;
using System.Text;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddTransient<INewSessionTokenProvider, NewSessionToken>();
builder.Services.AddTransient<INewSaltProvider, NewSaltProvider>();

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
    int iterations = 100_000;
    int byteHashLength = 32;

    byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(request.Password),
        newSalt.Salt,
        iterations,
        HashAlgorithmName.SHA512,
        byteHashLength
    );

    var user = await db.QuerySingleOrDefaultAsync<User>(
        "INSERT INTO Users (Username, PasswordHash, PasswordSalt, UserCreated) VALUES (@Username, @PasswordHash, @PasswordSalt, @CreationDate)" +
        "SELECT UserId, Username FROM Users WHERE Username = @Username",
        new { Username = request.Username, PasswordHash = hash, PasswordSalt = newSalt.Salt, CreationDate = DateTime.UtcNow });

    return Results.Ok(user);
});

app.MapPost("/login", async (LoginRequest request, SqlConnection db, INewSessionTokenProvider newSessionTokenProvider) =>
{
    byte[]? salt = await db.QuerySingleOrDefaultAsync<byte[]>("SELECT PasswordSalt FROM Users WHERE Username = @Username", new { Username = request.Username });

    if(salt is null)
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

    return Results.Ok(new { SessionToken = newSessionTokenProvider.Token });
});

app.Run();

internal sealed record User(int UserId, string Username);

internal sealed record LoginRequest(string Username, string Password);
internal sealed record CreateUserRequest(string Username, string Password);