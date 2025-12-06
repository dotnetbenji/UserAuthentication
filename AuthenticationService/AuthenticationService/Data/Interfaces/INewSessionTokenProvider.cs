namespace AuthenticationService.Data.Interfaces;

internal interface INewSessionTokenProvider
{
    byte[] Token { get; }
}