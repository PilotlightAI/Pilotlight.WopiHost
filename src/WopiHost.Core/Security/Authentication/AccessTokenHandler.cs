using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WopiHost.Abstractions;
using WopiHost.Core.Extensions;

namespace WopiHost.Core.Security.Authentication;

/// <summary>
/// Class facilitating authentication using an access token (access_token query parameter, access_token form field, or Authorization: Bearer header).
/// </summary>
/// <remarks>
/// Creates an instance of <see cref="AccessTokenHandler"/>.
/// </remarks>
/// <param name="options">The monitor for the options instance.</param>
/// <param name="securityHandler">An instance of a security handler.</param>
/// <param name="logger">The Microsoft.Extensions.Logging.ILoggerFactory.</param>
/// <param name="encoder">The System.Text.Encodings.Web.UrlEncoder.</param>
public class AccessTokenHandler(
    IWopiSecurityHandler securityHandler,
    IOptionsMonitor<AccessTokenAuthenticationOptions> options, 
    ILoggerFactory logger, 
    UrlEncoder encoder) : AuthenticationHandler<AccessTokenAuthenticationOptions>(options, logger, encoder)
{
    /// <summary>
    /// Handles authentication using the access token resolved by <see cref="HttpRequestExtensions.GetAccessToken(Microsoft.AspNetCore.Http.HttpRequest)"/>
    /// (query string first, then form data, then the Authorization: Bearer header).
    /// </summary>
    /// <returns><see cref="AuthenticateResult"/> set to <see cref="AuthenticateResult.Succeeded"/> when the token is valid and <see cref="AuthenticateResult.Failure"/> when the token is invalid or expired.</returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            //TODO: implement access_token_ttl https://learn.microsoft.com/openspecs/office_protocols/ms-wopi/adb48ba9-118a-43b6-82d7-9a508aad1583	

            if (Context.Request.Path.Value?.StartsWith("/wopi", StringComparison.OrdinalIgnoreCase) != true)
            {
                return AuthenticateResult.NoResult();
            }

            string token;
            if (Context.Request.Path.Value == "/wopibootstrapper")
            {
                //TODO: Implement properly: https://learn.microsoft.com/microsoft-365/cloud-storage-partner-program/rest/bootstrapper/bootstrap
                //Should be removed or replaced with bearer token check
                token = securityHandler.WriteToken(
                    await securityHandler.GenerateAccessToken("Anonymous", Convert.ToBase64String(Encoding.UTF8.GetBytes(".\\"))));
            }
            else
            {
                // Same resolver as WopiOriginValidationActionFilter (query string, then form, then Authorization: Bearer),
                // so the token that authenticates the request is the token its proof is validated against.
                token = Context.Request.GetAccessToken();
            }


            if (!string.IsNullOrEmpty(token))
            {
                var principal = await securityHandler.GetPrincipal(token);

                if (principal != null)
                {
                    var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Scheme.Name);

                    if (Options.SaveToken)
                    {
                        ticket.Properties.StoreTokens(
                        [
                            new AuthenticationToken { Name = AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, Value = token }
                        ]);
                    }
                    return AuthenticateResult.Success(ticket);
                }
                else
                {
                    LogFailure("PrincipalNotFound");
                    return AuthenticateResult.Fail("Principal not found.");
                }
            }
            else
            {
                LogFailure("TokenNotFound");
                return AuthenticateResult.Fail("Token not found.");
            }
        }
        catch (Exception ex)
        {
            LogFailure("Exception", ex);
            return AuthenticateResult.Fail(ex);
        }
    }

    private void LogFailure(string result, Exception? exception = null) =>
        WopiAuthenticationDiagnostics.LogFailure(
            Logger,
            LogLevel.Error,
            Context.Request,
            WopiAuthenticationDiagnostics.AUTHENTICATION_STAGE,
            result,
            exception);
}