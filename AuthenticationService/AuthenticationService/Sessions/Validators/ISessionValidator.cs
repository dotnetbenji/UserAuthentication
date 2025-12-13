namespace AuthenticationService.Sessions.Validators;

internal interface ISessionValidator
{
    Task<int?> Validate(SessionToken token);
}