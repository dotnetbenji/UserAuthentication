namespace AuthenticationService.Sessions.Resolvers;

internal interface ISessionResolver
{
    Task<string> CreateSession(User user);
    Task<List<string>> GetUserSessions(int userId);
}
