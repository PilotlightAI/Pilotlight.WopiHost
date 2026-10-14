using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Moq;
using WopiHost.Core.Infrastructure;
using WopiHost.Core.Security.Authentication;

namespace WopiHost.Core.Tests.Security.Authentication;

public class WopiOriginValidationActionFilterTests
{
    private readonly Mock<IWopiProofValidator> _proofValidator = new();
    private readonly CapturingLogger<WopiOriginValidationActionFilter> _logger = new();

    [Fact]
    public async Task BearerHeaderOnlyToken_IsTheTokenTheProofIsValidatedAgainst()
    {
        _proofValidator
            .Setup(x => x.ValidateProofAsync(It.IsAny<HttpContext>(), It.IsAny<string>()))
            .ReturnsAsync(true);
        var httpContext = CreateContext();
        httpContext.Request.Headers.Authorization = "Bearer header-token";
        var (context, next, nextCalled) = CreateFilterContext(httpContext);

        await new WopiOriginValidationActionFilter(_proofValidator.Object, _logger).OnActionExecutionAsync(context, next);

        _proofValidator.Verify(x => x.ValidateProofAsync(httpContext, "header-token"), Times.Once);
        Assert.True(nextCalled());
        Assert.Empty(_logger.PresenceLines);
    }

    [Fact]
    public async Task InvalidProof_Returns500_AndLogsPresenceLine()
    {
        _proofValidator
            .Setup(x => x.ValidateProofAsync(It.IsAny<HttpContext>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        var httpContext = CreateContext();
        httpContext.Request.QueryString = QueryString.Create(AccessTokenDefaults.ACCESS_TOKEN_QUERY_NAME, "query-token");
        httpContext.Request.Headers[WopiHeaders.TIMESTAMP] = "638000000000000000";
        httpContext.Request.Headers[WopiHeaders.WOPI_OVERRIDE] = "PUT";
        httpContext.Request.Headers[WopiHeaders.CORRELATION_ID] = "corr-456";
        var (context, next, nextCalled) = CreateFilterContext(httpContext);

        await new WopiOriginValidationActionFilter(_proofValidator.Object, _logger).OnActionExecutionAsync(context, next);

        var result = Assert.IsType<StatusCodeResult>(context.Result);
        Assert.Equal(StatusCodes.Status500InternalServerError, result.StatusCode);
        Assert.False(nextCalled());

        var entry = Assert.Single(_logger.PresenceLines);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal("proof validation", entry.Values["Stage"]);
        Assert.Equal("ProofInvalid", entry.Values["Result"]);
        Assert.Equal("PUT", entry.Values["WopiOperation"]);
        Assert.Equal("corr-456", entry.Values["CorrelationId"]);
        Assert.Equal(true, entry.Values["HasQueryToken"]);
        Assert.Equal(false, entry.Values["HasFormToken"]);
        Assert.Equal(false, entry.Values["HasBearerToken"]);
        Assert.Equal(false, entry.Values["HasProof"]);
        Assert.Equal(true, entry.Values["HasTimeStamp"]);
        Assert.DoesNotContain("query-token", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingToken_Returns500_AndLogsPresenceLine()
    {
        var httpContext = CreateContext();
        httpContext.Request.Headers[WopiHeaders.PROOF] = "proof-value";
        var (context, next, nextCalled) = CreateFilterContext(httpContext);

        await new WopiOriginValidationActionFilter(_proofValidator.Object, _logger).OnActionExecutionAsync(context, next);

        Assert.Equal(StatusCodes.Status500InternalServerError, httpContext.Response.StatusCode);
        Assert.False(nextCalled());
        _proofValidator.Verify(x => x.ValidateProofAsync(It.IsAny<HttpContext>(), It.IsAny<string>()), Times.Never);

        var entry = Assert.Single(_logger.PresenceLines);
        Assert.Equal("TokenNotFound", entry.Values["Result"]);
        Assert.Equal(true, entry.Values["HasProof"]);
        Assert.DoesNotContain("proof-value", entry.Message, StringComparison.Ordinal);
    }

    private static DefaultHttpContext CreateContext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Path = "/wopi/files/1";
        return httpContext;
    }

    private static (ActionExecutingContext Context, ActionExecutionDelegate Next, Func<bool> NextCalled) CreateFilterContext(HttpContext httpContext)
    {
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var filters = new List<IFilterMetadata>();
        var controller = new object();
        var context = new ActionExecutingContext(actionContext, filters, new Dictionary<string, object?>(), controller);
        var called = false;
        ActionExecutionDelegate next = () =>
        {
            called = true;
            return Task.FromResult(new ActionExecutedContext(actionContext, filters, controller));
        };
        return (context, next, () => called);
    }
}
