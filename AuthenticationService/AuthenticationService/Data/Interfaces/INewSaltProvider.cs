namespace AuthenticationService.Data.Interfaces;

internal interface INewSaltProvider
{
    byte[] Salt { get; }
}