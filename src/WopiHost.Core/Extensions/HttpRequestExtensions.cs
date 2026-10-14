using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using WopiHost.Core.Infrastructure;
using WopiHost.Core.Security.Authentication;

namespace WopiHost.Core.Extensions;

/// <summary>
/// Extension methods for <see cref="HttpRequest"/>.
/// </summary>
public static class HttpRequestExtensions
{
    /// <summary>
    /// Gets the access token from the request in various formats (query string, form data, or authorization header).
    /// </summary>
    /// <remarks>
    /// According to Microsoft documentation:
    /// "WOPI clients aren't required to pass the access token in the Authorization header, but they must send it as a URL parameter in all WOPI operations.
    /// So, for maximum compatibility, WOPI hosts should either use the URL parameter in all cases, or fall back to it if the Authorization header isn't included in the request."
    /// 
    /// This method follows this guidance by first checking the URL parameter (query string), then form data, and finally falling back to the Authorization header.
    /// </remarks>
    /// <param name="request">The HTTP request.</param>
    /// <returns>The access token if found; otherwise, an empty string.</returns>
    public static string GetAccessToken(this HttpRequest request)
    {
        // First try to get from query string
        if (TryGetQueryToken(request, out var token))
        {
            return token;
        }

        // Then try to get from form data in POST requests
        if (TryGetFormToken(request, out token))
        {
            return token;
        }

        // Lastly check header (less common)
        if (TryGetBearerToken(request, out token))
        {
            return token;
        }

        return string.Empty;
    }

    /// <summary>
    /// Reports which access token carriers and WOPI proof headers are present on the request, without reading out any of their values.
    /// Used for diagnostics only; never throws.
    /// </summary>
    /// <param name="request">The HTTP request.</param>
    internal static AccessTokenPresence GetAccessTokenPresence(this HttpRequest request)
    {
        bool hasFormToken;
        try
        {
            hasFormToken = TryGetFormToken(request, out _);
        }
        catch (Exception)
        {
            // A form that cannot be read carries no usable token; diagnostics must not fail the request.
            hasFormToken = false;
        }

        return new AccessTokenPresence(
            QueryToken: TryGetQueryToken(request, out _),
            FormToken: hasFormToken,
            BearerToken: TryGetBearerToken(request, out _),
            Proof: HasHeader(request, WopiHeaders.PROOF),
            TimeStamp: HasHeader(request, WopiHeaders.TIMESTAMP));
    }

    private static bool TryGetQueryToken(HttpRequest request, out string token)
    {
        if (request.Query.TryGetValue(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, out StringValues tokenFromQuery) &&
            !StringValues.IsNullOrEmpty(tokenFromQuery))
        {
            token = tokenFromQuery.ToString();
            return true;
        }

        token = string.Empty;
        return false;
    }

    private static bool TryGetFormToken(HttpRequest request, out string token)
    {
        if (request.HasFormContentType &&
            request.Form.TryGetValue(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, out StringValues tokenFromForm) &&
            !StringValues.IsNullOrEmpty(tokenFromForm))
        {
            token = tokenFromForm.ToString();
            return true;
        }

        token = string.Empty;
        return false;
    }

    private static bool TryGetBearerToken(HttpRequest request, out string token)
    {
        if (request.Headers.TryGetValue("Authorization", out StringValues authHeader) &&
            !StringValues.IsNullOrEmpty(authHeader))
        {
            var header = authHeader.ToString();
            if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = header["Bearer ".Length..].Trim();
                return token.Length > 0;
            }
        }

        token = string.Empty;
        return false;
    }

    private static bool HasHeader(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out StringValues value) && !StringValues.IsNullOrEmpty(value);
    
    /// <summary>
    /// Proxy-aware construction of URL request.
    /// </summary>
    public static string GetProxyAwareRequestUrl(this HttpRequest request)
    {
        var (scheme, host, pathBase, path, queryString) = request.GetProxyAwareUrlParts();
        
        return $"{scheme}://{host}{pathBase}{path}{queryString}";
    }

    /// <summary>
    /// Get's the Uri parts to construct URL's.
    /// </summary>
    public static (string? scheme, string? host, string? pathBase, string? path, string? queryString)
        GetProxyAwareUrlParts(this HttpRequest request)
    {
        var scheme = request.Headers.ContainsKey("X-Forwarded-Proto") 
            ? request.Headers["X-Forwarded-Proto"].ToString() 
            : request.Scheme;
        
        var host = request.Headers.ContainsKey("X-Forwarded-Host") 
            ? request.Headers["X-Forwarded-Host"].ToString() 
            : request.Host.Value;
        
        var pathBase = request.Headers.ContainsKey("X-Forwarded-PathBase") 
            ? request.Headers["X-Forwarded-PathBase"].ToString() 
            : request.PathBase.Value;
        
        var path = request.Path.Value;
        var queryString = request.QueryString.Value;
        
        return (scheme, host, pathBase, path, queryString);
    }
} 