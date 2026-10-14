using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Moq;
using WopiHost.Core.Extensions;
using WopiHost.Core.Infrastructure;
using WopiHost.Core.Security.Authentication;

namespace WopiHost.Core.Tests.Extensions;

public class HttpRequestExtensionsTests
{
    [Fact]
    public void GetProxyAwareRequestUrl_WithoutProxyHeaders_ReturnsStandardUrl()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "https",
            host: "example.com",
            pathBase: "/api",
            path: "/wopi/files",
            queryString: "?access_token=123"
        );

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://example.com/api/wopi/files?access_token=123", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithProxyHeaders_UsesProxyValues()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "http",
            host: "internal.server",
            pathBase: "/internal",
            path: "/wopi/files",
            queryString: "?access_token=123"
        );

        AddProxyHeaders(request, 
            forwardedProto: "https", 
            forwardedHost: "proxy.example.com", 
            forwardedPathBase: "/external");

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://proxy.example.com/external/wopi/files?access_token=123", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithPartialProxyHeaders_UsesProxyAndOriginalValues()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "http",
            host: "internal.server",
            pathBase: "/internal",
            path: "/wopi/files",
            queryString: "?access_token=123"
        );

        // Only set proto and host headers, not pathBase
        AddProxyHeaders(request, 
            forwardedProto: "https", 
            forwardedHost: "proxy.example.com");

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://proxy.example.com/internal/wopi/files?access_token=123", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithEmptyPathBase_HandlesCorrectly()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "https",
            host: "example.com",
            pathBase: "",
            path: "/wopi/files",
            queryString: "?access_token=123"
        );

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://example.com/wopi/files?access_token=123", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithoutQueryString_HandlesCorrectly()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "https",
            host: "example.com",
            pathBase: "/api",
            path: "/wopi/files",
            queryString: ""
        );

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://example.com/api/wopi/files", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithRootPath_HandlesCorrectly()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "https",
            host: "example.com",
            pathBase: "",
            path: "/",
            queryString: ""
        );

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://example.com/", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithComplexPath_HandlesCorrectly()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "https",
            host: "example.com",
            pathBase: "/wopi-host",
            path: "/wopi/files/123/contents",
            queryString: "?access_token=abc&version=1"
        );

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://example.com/wopi-host/wopi/files/123/contents?access_token=abc&version=1", result);
    }

    [Fact]
    public void GetProxyAwareRequestUrl_WithNullValues_HandlesGracefully()
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "https",
            host: "example.com",
            pathBase: null,
            path: null,
            queryString: null
        );

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        Assert.Equal("https://example.com", result);
    }

    [Theory]
    [InlineData("X-Forwarded-Proto", "https")]
    [InlineData("X-Forwarded-Host", "proxy.example.com")]
    [InlineData("X-Forwarded-PathBase", "/external")]
    public void GetProxyAwareRequestUrl_WithSingleProxyHeader_UsesProxyValueForThatHeader(string headerName, string headerValue)
    {
        // Arrange
        var request = CreateMockRequest(
            scheme: "http",
            host: "internal.server",
            pathBase: "/internal",
            path: "/wopi/files",
            queryString: "?test=1"
        );

        var headers = new HeaderDictionary
        {
            [headerName] = headerValue
        };
        Mock.Get(request).Setup(r => r.Headers).Returns(headers);

        // Act
        var result = request.GetProxyAwareRequestUrl();

        // Assert
        switch (headerName)
        {
            case "X-Forwarded-Proto":
                Assert.StartsWith("https://", result);
                break;
            case "X-Forwarded-Host":
                Assert.Contains("proxy.example.com", result);
                break;
            case "X-Forwarded-PathBase":
                Assert.Contains("/external/wopi/files", result);
                break;
        }
    }

    [Fact]
    public void GetAccessToken_WithBearerHeaderOnly_ReturnsHeaderToken()
    {
        var request = CreateTokenRequest(bearerToken: "header-token");

        Assert.Equal("header-token", request.GetAccessToken());
    }

    [Fact]
    public void GetAccessToken_WithQueryAndBearerHeader_PrefersQueryToken()
    {
        var request = CreateTokenRequest(queryToken: "query-token", bearerToken: "header-token");

        Assert.Equal("query-token", request.GetAccessToken());
    }

    [Fact]
    public void GetAccessToken_WithFormAndBearerHeader_PrefersFormToken()
    {
        var request = CreateTokenRequest(formToken: "form-token", bearerToken: "header-token");

        Assert.Equal("form-token", request.GetAccessToken());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Bearer ")]
    [InlineData("Bearer    ")]
    [InlineData("Basic dXNlcjpwYXNz")]
    public void GetAccessToken_WithoutUsableToken_ReturnsEmpty(string? authorizationHeader)
    {
        var request = CreateTokenRequest();
        if (authorizationHeader is not null)
        {
            request.Headers.Authorization = authorizationHeader;
        }

        Assert.Equal(string.Empty, request.GetAccessToken());
    }

    [Fact]
    public void GetAccessTokenPresence_ReportsEachCarrierAndProofHeader()
    {
        var request = CreateTokenRequest(queryToken: "query-token", formToken: "form-token", bearerToken: "header-token");
        request.Headers[WopiHeaders.PROOF] = "proof";
        request.Headers[WopiHeaders.TIMESTAMP] = "638000000000000000";

        var presence = request.GetAccessTokenPresence();

        Assert.Equal(new AccessTokenPresence(QueryToken: true, FormToken: true, BearerToken: true, Proof: true, TimeStamp: true), presence);
    }

    [Fact]
    public void GetAccessTokenPresence_WithNothing_ReportsAllFalse()
    {
        var presence = CreateTokenRequest().GetAccessTokenPresence();

        Assert.Equal(default, presence);
    }

    [Fact]
    public void GetAccessTokenPresence_WithUnreadableForm_ReportsNoFormTokenWithoutThrowing()
    {
        var request = CreateTokenRequest(bearerToken: "header-token");
        request.ContentType = "multipart/form-data"; // no boundary: reading the form throws

        var presence = request.GetAccessTokenPresence();

        Assert.False(presence.FormToken);
        Assert.True(presence.BearerToken);
    }

    private static HttpRequest CreateTokenRequest(string? queryToken = null, string? formToken = null, string? bearerToken = null)
    {
        var context = new DefaultHttpContext();
        var request = context.Request;
        request.Method = HttpMethods.Post;
        request.Path = "/wopi/files/1";
        if (queryToken is not null)
        {
            request.QueryString = QueryString.Create(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, queryToken);
        }
        if (formToken is not null)
        {
            request.ContentType = "application/x-www-form-urlencoded";
            request.Body = new MemoryStream(Encoding.UTF8.GetBytes(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME + "=" + Uri.EscapeDataString(formToken)));
        }
        if (bearerToken is not null)
        {
            request.Headers.Authorization = "Bearer " + bearerToken;
        }
        return request;
    }

    private static HttpRequest CreateMockRequest(string scheme, string host, string? pathBase, string? path, string? queryString)
    {
        var request = new Mock<HttpRequest>();
        var headers = new HeaderDictionary();
        
        request.Setup(r => r.Scheme).Returns(scheme);
        request.Setup(r => r.Host).Returns(new HostString(host));
        request.Setup(r => r.PathBase).Returns(new PathString(pathBase));
        request.Setup(r => r.Path).Returns(new PathString(path));
        request.Setup(r => r.QueryString).Returns(new QueryString(queryString));
        request.Setup(r => r.Headers).Returns(headers);

        return request.Object;
    }

    private static void AddProxyHeaders(HttpRequest request, string? forwardedProto = null, 
        string? forwardedHost = null, string? forwardedPathBase = null)
    {
        var headers = request.Headers;
        
        if (forwardedProto != null)
            headers["X-Forwarded-Proto"] = forwardedProto;
        
        if (forwardedHost != null)
            headers["X-Forwarded-Host"] = forwardedHost;
        
        if (forwardedPathBase != null)
            headers["X-Forwarded-PathBase"] = forwardedPathBase;
    }
} 