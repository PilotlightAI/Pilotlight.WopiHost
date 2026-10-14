using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Moq;
using WopiHost.Abstractions;
using WopiHost.Core.Infrastructure;
using WopiHost.Core.Security.Authentication;

namespace WopiHost.Core.Tests.Security.Authentication;

public class AccessTokenHandlerTests
{
    private readonly Mock<IWopiSecurityHandler> _securityHandlerMock;
    private readonly Mock<UrlEncoder> _urlEncoderMock;
    private readonly AccessTokenHandler _accessTokenHandler;
    private readonly AuthenticationScheme scheme;

    public AccessTokenHandlerTests()
    {
        _securityHandlerMock = new Mock<IWopiSecurityHandler>();
        var options = new Mock<IOptionsMonitor<AccessTokenAuthenticationOptions>>();
        options
            .Setup(x => x.Get(It.IsAny<string>()))
            .Returns(new AccessTokenAuthenticationOptions());
        var logger = new Mock<ILogger<AccessTokenHandler>>();
        var loggerFactory = new Mock<ILoggerFactory>();
        loggerFactory.Setup(x => x.CreateLogger(It.IsAny<string>())).Returns(logger.Object);
        _urlEncoderMock = new Mock<UrlEncoder>();

        scheme = new AuthenticationScheme(
            AccessTokenDefaults.AUTHENTICATION_SCHEME,
            null,
            typeof(AccessTokenHandler));

        _accessTokenHandler = new AccessTokenHandler(
            _securityHandlerMock.Object,
            options.Object,
            loggerFactory.Object,
            _urlEncoderMock.Object
        );
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldReturnNoResult_WhenNotWopiPath()
    {
        // Arrange
        var context = new DefaultHttpContext()
        {
            Request =
            {
                Path = "/whatever",
            }
        };
        await _accessTokenHandler.InitializeAsync(scheme, context);

        // Act
        var result = await _accessTokenHandler.AuthenticateAsync();

        // Assert
        Assert.True(result.None);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldReturnSuccess_WhenTokenIsValid()
    {
        // Arrange
        var token = "valid_token";
        var principal = new ClaimsPrincipal(new ClaimsIdentity("test"));
        _securityHandlerMock
            .Setup(x => x.GetPrincipal(token, default))
            .ReturnsAsync(principal);
        var context = new DefaultHttpContext()
        {
            Request =
            {
                Path = "/wopi",
                Query = new QueryCollection(new Dictionary<string, StringValues>
                {
                    { AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, token }
                })
            }
        };
        await _accessTokenHandler.InitializeAsync(scheme, context);

        // Act
        var result = await _accessTokenHandler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldReturnFailure_WhenTokenIsInvalid()
    {
        // Arrange
        var token = "invalid_token";
        _securityHandlerMock
            .Setup(x => x.GetPrincipal(token, default))
            .ReturnsAsync((ClaimsPrincipal?)null);
        var context = new DefaultHttpContext()
        {
            Request =
            {
                Query = new QueryCollection(new Dictionary<string, StringValues>
                {
                    { AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, token }
                })
            }
        };
        await _accessTokenHandler.InitializeAsync(scheme, context);

        // Act
        var result = await _accessTokenHandler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldReturnFailure_WhenTokenIsMissing()
    {
        // Arrange
        var context = new DefaultHttpContext();
        await _accessTokenHandler.InitializeAsync(scheme, context);

        // Act
        var result = await _accessTokenHandler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldReturnFailure_WhenExceptionIsThrown()
    {
        // Arrange
        var token = "valid_token";
        _securityHandlerMock
            .Setup(x => x.GetPrincipal(token, default))
            .ThrowsAsync(new Exception("Test exception"));
        var context = new DefaultHttpContext()
        {
            Request =
            {
                Query = new QueryCollection(new Dictionary<string, StringValues>
                {
                    { AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, token }
                })
            }
        };
        await _accessTokenHandler.InitializeAsync(scheme, context);

        // Act
        var result = await _accessTokenHandler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldReturnSuccess_WhenTokenIsOnlyInBearerHeader()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity("test"));
        _securityHandlerMock
            .Setup(x => x.GetPrincipal("header-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(principal);
        var context = CreateWopiContext(bearerToken: "header-token");
        await _accessTokenHandler.InitializeAsync(scheme, context);

        var result = await _accessTokenHandler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Same(principal, result.Principal);
        // The saved token (used to build WopiSrc URLs) is the token that authenticated the request.
        Assert.Equal("header-token", result.Properties!.GetTokenValue(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME));
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldUseQueryToken_WhenQueryAndBearerHeaderArePresent()
    {
        var queryPrincipal = new ClaimsPrincipal(new ClaimsIdentity("query"));
        var headerPrincipal = new ClaimsPrincipal(new ClaimsIdentity("header"));
        _securityHandlerMock
            .Setup(x => x.GetPrincipal("query-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(queryPrincipal);
        _securityHandlerMock
            .Setup(x => x.GetPrincipal("header-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(headerPrincipal);
        var context = CreateWopiContext(queryToken: "query-token", bearerToken: "header-token");
        await _accessTokenHandler.InitializeAsync(scheme, context);

        var result = await _accessTokenHandler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Same(queryPrincipal, result.Principal);
        Assert.Equal("query-token", result.Properties!.GetTokenValue(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME));
        _securityHandlerMock.Verify(x => x.GetPrincipal("header-token", It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldFail_WhenQueryTokenIsInvalid_EvenIfBearerHeaderIsValid()
    {
        _securityHandlerMock
            .Setup(x => x.GetPrincipal("invalid-query-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync((ClaimsPrincipal?)null);
        _securityHandlerMock
            .Setup(x => x.GetPrincipal("valid-header-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("header")));
        var context = CreateWopiContext(queryToken: "invalid-query-token", bearerToken: "valid-header-token");
        var logger = new CapturingLogger();
        var handler = CreateHandler(logger);
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        _securityHandlerMock.Verify(x => x.GetPrincipal("valid-header-token", It.IsAny<CancellationToken>()), Times.Never);
        await AssertChallengeIs401(handler, context);

        var entry = Assert.Single(logger.PresenceLines);
        Assert.Equal("PrincipalNotFound", entry.Values["Result"]);
        Assert.Equal(true, entry.Values["HasQueryToken"]);
        Assert.Equal(true, entry.Values["HasBearerToken"]);
        AssertNoSecrets(entry, "invalid-query-token", "valid-header-token");
    }

    [Theory]
    [InlineData("expired", true)]
    [InlineData("expired", false)]
    [InlineData("malformed", true)]
    [InlineData("malformed", false)]
    [InlineData("wrong-key", true)]
    [InlineData("wrong-key", false)]
    public async Task HandleAuthenticateAsync_ShouldFail_WhenJwtIsExpiredOrMalformed(string kind, bool inBearerHeader)
    {
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("test-signing-key-test-signing-key-0123456789"));
        var jwt = new JwtSecurityTokenHandler();
        string token = kind switch
        {
            "expired" => jwt.WriteToken(jwt.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity([new Claim(ClaimTypes.Name, "user")]),
                IssuedAt = DateTime.UtcNow.AddHours(-2),
                NotBefore = DateTime.UtcNow.AddHours(-2),
                Expires = DateTime.UtcNow.AddHours(-1),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
            })),
            "wrong-key" => jwt.WriteToken(jwt.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity([new Claim(ClaimTypes.Name, "user")]),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes("another-signing-key-another-signing-key-01")),
                    SecurityAlgorithms.HmacSha256)
            })),
            _ => "not-a-jwt"
        };
        // Real JWT validation, the way a security handler does it: an invalid token yields no principal.
        _securityHandlerMock
            .Setup(x => x.GetPrincipal(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string t, CancellationToken ct) =>
            {
                try
                {
                    return jwt.ValidateToken(t, new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = signingKey,
                        ClockSkew = TimeSpan.Zero
                    }, out _);
                }
                catch (Exception)
                {
                    return null;
                }
            });
        var context = inBearerHeader ? CreateWopiContext(bearerToken: token) : CreateWopiContext(queryToken: token);
        await _accessTokenHandler.InitializeAsync(scheme, context);

        var result = await _accessTokenHandler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        _securityHandlerMock.Verify(x => x.GetPrincipal(token, It.IsAny<CancellationToken>()), Times.Once);
        await AssertChallengeIs401(_accessTokenHandler, context);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldFail_WhenBearerTokenValidationThrows()
    {
        _securityHandlerMock
            .Setup(x => x.GetPrincipal("header-token", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ArgumentException("IDX12741: JWT is malformed."));
        var context = CreateWopiContext(bearerToken: "header-token");
        var logger = new CapturingLogger();
        var handler = CreateHandler(logger);
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.IsType<ArgumentException>(result.Failure);
        await AssertChallengeIs401(handler, context);
        var entry = Assert.Single(logger.PresenceLines);
        Assert.Equal("Exception", entry.Values["Result"]);
        Assert.IsType<ArgumentException>(entry.Exception);
        AssertNoSecrets(entry, "header-token");
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldFailAndLogPresenceLine_WhenNoTokenIsPresent()
    {
        var context = CreateWopiContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Headers[WopiHeaders.WOPI_OVERRIDE] = "LOCK";
        context.Request.Headers[WopiHeaders.CORRELATION_ID] = "corr-123";
        context.Request.Headers[WopiHeaders.PROOF] = "proof-value";
        context.Request.Headers[WopiHeaders.TIMESTAMP] = "638000000000000000";
        var logger = new CapturingLogger();
        var handler = CreateHandler(logger);
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Token not found.", result.Failure?.Message);
        _securityHandlerMock.Verify(x => x.GetPrincipal(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        await AssertChallengeIs401(handler, context);

        var entry = Assert.Single(logger.PresenceLines);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal(WopiAuthenticationDiagnostics.MESSAGE_TEMPLATE, entry.Values["{OriginalFormat}"]);
        Assert.Equal("authentication", entry.Values["Stage"]);
        Assert.Equal("TokenNotFound", entry.Values["Result"]);
        Assert.Equal("POST", entry.Values["Method"]);
        Assert.Equal("/wopi/files/1", entry.Values["Path"]);
        Assert.Equal("LOCK", entry.Values["WopiOperation"]);
        Assert.Equal("corr-123", entry.Values["CorrelationId"]);
        Assert.Equal(false, entry.Values["HasQueryToken"]);
        Assert.Equal(false, entry.Values["HasFormToken"]);
        Assert.Equal(false, entry.Values["HasBearerToken"]);
        Assert.Equal(true, entry.Values["HasProof"]);
        Assert.Equal(true, entry.Values["HasTimeStamp"]);
        AssertNoSecrets(entry, "proof-value", "638000000000000000");
    }

    private AccessTokenHandler CreateHandler(ILogger logger)
    {
        var options = new Mock<IOptionsMonitor<AccessTokenAuthenticationOptions>>();
        options
            .Setup(x => x.Get(It.IsAny<string>()))
            .Returns(new AccessTokenAuthenticationOptions());
        var loggerFactory = new Mock<ILoggerFactory>();
        loggerFactory.Setup(x => x.CreateLogger(It.IsAny<string>())).Returns(logger);
        return new AccessTokenHandler(_securityHandlerMock.Object, options.Object, loggerFactory.Object, _urlEncoderMock.Object);
    }

    private static DefaultHttpContext CreateWopiContext(string? queryToken = null, string? bearerToken = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/wopi/files/1";
        if (queryToken is not null)
        {
            context.Request.QueryString = QueryString.Create(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, queryToken);
        }
        if (bearerToken is not null)
        {
            context.Request.Headers.Authorization = "Bearer " + bearerToken;
        }
        return context;
    }

    private static async Task AssertChallengeIs401(AccessTokenHandler handler, HttpContext context)
    {
        await handler.ChallengeAsync(new AuthenticationProperties());
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    private static void AssertNoSecrets(CapturingLogger.Entry entry, params string[] secrets)
    {
        foreach (var secret in secrets)
        {
            Assert.DoesNotContain(secret, entry.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(entry.Values.Values, v => v is string s && s.Contains(secret, StringComparison.Ordinal));
        }
        Assert.DoesNotContain("?", entry.Values["Path"] as string ?? string.Empty, StringComparison.Ordinal);
    }
}
