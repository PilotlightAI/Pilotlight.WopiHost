using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using WopiHost.Core.Extensions;
using WopiHost.Core.Infrastructure;

namespace WopiHost.Core.Security.Authentication;

/// <summary>
/// Which access token carriers and WOPI proof headers a request has. Holds presence only, never a value.
/// </summary>
/// <param name="QueryToken">The access_token query parameter is present and non-empty.</param>
/// <param name="FormToken">The access_token form field is present and non-empty.</param>
/// <param name="BearerToken">An Authorization: Bearer header with a non-empty token is present.</param>
/// <param name="Proof">The X-WOPI-Proof header is present.</param>
/// <param name="TimeStamp">The X-WOPI-TimeStamp header is present.</param>
internal readonly record struct AccessTokenPresence(bool QueryToken, bool FormToken, bool BearerToken, bool Proof, bool TimeStamp);

/// <summary>
/// Token-free diagnostics for failed WOPI authentication and proof validation.
/// </summary>
internal static class WopiAuthenticationDiagnostics
{
    internal const string AUTHENTICATION_STAGE = "authentication";
    internal const string PROOF_VALIDATION_STAGE = "proof validation";

    internal const string MESSAGE_TEMPLATE =
        "WOPI {Stage} failed: {Result} for {Method} {Path} (operation {WopiOperation}, correlation id {CorrelationId}); " +
        "access token in query {HasQueryToken}, form {HasFormToken}, bearer {HasBearerToken}; " +
        "proof header {HasProof}, timestamp header {HasTimeStamp}";

    /// <summary>
    /// Logs one structured line describing a failed request: presence booleans, the WOPI operation and correlation id.
    /// Never logs a token, a proof value or a query string.
    /// </summary>
    internal static void LogFailure(ILogger logger, LogLevel level, HttpRequest request, string stage, string result, Exception? exception = null)
    {
        if (!logger.IsEnabled(level))
        {
            return;
        }

        var presence = request.GetAccessTokenPresence();
        logger.Log(
            level,
            exception,
            MESSAGE_TEMPLATE,
            stage,
            result,
            request.Method,
            request.Path.Value,
            GetHeader(request, WopiHeaders.WOPI_OVERRIDE),
            GetHeader(request, WopiHeaders.CORRELATION_ID),
            presence.QueryToken,
            presence.FormToken,
            presence.BearerToken,
            presence.Proof,
            presence.TimeStamp);
    }

    private static string? GetHeader(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out StringValues value) && !StringValues.IsNullOrEmpty(value)
            ? value.ToString()
            : null;
}
