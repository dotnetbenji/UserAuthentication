namespace AuthenticationService.Sessions.Validators;

internal interface ISessionValidator
{
    Task<User?> Validate(SessionToken token);
}