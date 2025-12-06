namespace AuthenticationService.Data.Interfaces;

internal interface INewSessionTokenProvider
{
    string Token { get; }
}