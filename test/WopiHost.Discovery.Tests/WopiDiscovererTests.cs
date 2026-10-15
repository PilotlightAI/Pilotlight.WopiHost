using System.Diagnostics.CodeAnalysis;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WopiHost.Discovery.Enumerations;

namespace WopiHost.Discovery.Tests;

public class WopiDiscovererTests : IDisposable
{
    private WopiDiscoverer? _wopiDiscoverer;
    private const string XmlOos2016 = "OOS2016_discovery.xml";
    private const string XmlOwa2013 = "OWA2013_discovery.xml";
    private const string XmlOo2019 = "OO2019_discovery.xml";
    private const string XmlInvalid = "INVALID_discovery.xml";

    public WopiDiscovererTests()
    {
    }

    public void Dispose() => _wopiDiscoverer?.Dispose();

    [Fact]
    public async Task ConcurrentProofKeyLookups_FetchOnce()
    {
        var provider = new GatedDiscoveryProvider();
        using var discoverer = new WopiDiscoverer(provider, Options.Create(new DiscoveryOptions()));
        var reads = Enumerable.Range(0, 16).Select(_ => discoverer.GetProofKeysAsync()).ToArray();
        await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        provider.Release.SetResult(true);

        var keys = await Task.WhenAll(reads).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, provider.Calls);
        Assert.All(keys, key => Assert.Equal("current", key.Value));
    }

    [Fact]
    public async Task ConcurrentAppLookups_FetchOnce()
    {
        var provider = new GatedDiscoveryProvider();
        using var discoverer = new WopiDiscoverer(provider, Options.Create(new DiscoveryOptions { NetZone = NetZoneEnum.ExternalHttps }));
        var reads = Enumerable.Range(0, 16).Select(_ => discoverer.SupportsExtensionAsync("docx")).ToArray();
        await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        provider.Release.SetResult(true);

        var supported = await Task.WhenAll(reads).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, provider.Calls);
        Assert.All(supported, value => Assert.True(value));
    }

    [Fact]
    public async Task OwnedDiscoverer_DisposesAfterUse()
    {
        var discoveryProvider = new GatedDiscoveryProvider();
        discoveryProvider.Release.SetResult(true);
        var services = new ServiceCollection();
        services.AddWopiDiscovery<TestDiscoveryOptions>(options => options.NetZone = NetZoneEnum.ExternalHttps);
        services.AddSingleton<IDiscoveryFileProvider>(discoveryProvider);
        using var owner = services.BuildServiceProvider();
        var discoverer = Assert.IsType<WopiDiscoverer>(owner.GetRequiredService<IDiscoverer>());
        Assert.Same(discoverer, owner.GetRequiredService<IDiscoverer>());
        Assert.True(await discoverer.SupportsExtensionAsync("docx"));
        Assert.Equal("current", (await discoverer.GetProofKeysAsync()).Value);
        Assert.Equal(2, discoveryProvider.Calls);

        owner.Dispose();
        owner.Dispose();
        discoverer.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => discoverer.GetProofKeysAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => discoverer.SupportsExtensionAsync("docx"));
    }

    private sealed class TestDiscoveryOptions : IDiscoveryOptions
    {
        public Uri? ClientUrl => new("https://office.example");
    }

    private sealed class GatedDiscoveryProvider : IDiscoveryFileProvider
    {
        public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Calls;

        public async Task<XElement> GetDiscoveryXmlAsync()
        {
            Interlocked.Increment(ref Calls);
            Entered.TrySetResult(true);
            await Release.Task;
            return XElement.Parse("""
                <wopi-discovery>
                  <net-zone name="external-https"><app name="Word"><action name="edit" ext="docx" urlsrc="https://office.example/edit" /></app></net-zone>
                  <proof-key value="current" oldvalue="old" />
                </wopi-discovery>
                """);
        }
    }

    [MemberNotNull(nameof(_wopiDiscoverer))]
    private void InitDiscoverer(string fileName, NetZoneEnum netZone) => 
        _wopiDiscoverer = new WopiDiscoverer(new FileSystemDiscoveryFileProvider(Path.Combine(AppContext.BaseDirectory, fileName)), Options.Create(new DiscoveryOptions { NetZone = netZone }));

    [Theory]
    [InlineData(NetZoneEnum.ExternalHttps, "xlsm", WopiActionEnum.LegacyWebService, "https://excel.officeapps.live.com/x/_vti_bin/excelserviceinternal.asmx?<ui=UI_LLCC&><rs=DC_LLCC&><dchat=DISABLE_CHAT&><hid=HOST_SESSION_ID&><sc=SESSION_CONTEXT&><wopisrc=WOPI_SOURCE&>", XmlOo2019)]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", WopiActionEnum.MobileView, "http://owaserver/x/_layouts/xlviewerinternal.aspx?<ui=UI_LLCC&><rs=DC_LLCC&><dchat=DISABLE_CHAT&>", XmlOo2019)]
    [InlineData(NetZoneEnum.ExternalHttps, "xlsx", WopiActionEnum.MobileView, "https://excel.officeapps.live.com/x/_layouts/xlviewerinternal.aspx?<ui=UI_LLCC&><rs=DC_LLCC&><dchat=DISABLE_CHAT&><hid=HOST_SESSION_ID&><sc=SESSION_CONTEXT&><wopisrc=WOPI_SOURCE&>", XmlOo2019)]
    [InlineData(NetZoneEnum.InternalHttp, "ods", WopiActionEnum.Edit, "http://owaserver/x/_layouts/xlviewerinternal.aspx?edit=1&<ui=UI_LLCC&><rs=DC_LLCC&>", XmlOwa2013)]
    public async Task NetZoneTests(NetZoneEnum netZone, string extension, WopiActionEnum action, string expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetUrlTemplateAsync(extension, action);

        // Assert
        Assert.Equal(expectedValue, result);
    }

    [Fact]
    public async Task InvalidNetZone()
    {
        // Arrange
        InitDiscoverer(XmlInvalid, NetZoneEnum.InternalHttp);

        // Act
        var result = await _wopiDiscoverer.GetAppsAsync();

        // Assert
        Assert.Empty(result.Elements());
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", XmlOos2016)]
    public async Task SupportedExtension(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.SupportsExtensionAsync(extension);

        // Assert
        Assert.True(result, $"{extension} should be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "XLSX", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "DOCX", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "XlSx", XmlOos2016)]
    public async Task CaseInsensitiveSupportedExtension(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.SupportsExtensionAsync(extension);

        // Assert
        Assert.True(result, $"{extension} should be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "html", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "txt", XmlOos2016)]
    public async Task NonSupportedExtension(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.SupportsExtensionAsync(extension);

        // Assert
        Assert.False(result, $"{extension} should not be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "html", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "txt", XmlOos2016)]
    public async Task NonSupportedExtensionWithAction(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.SupportsActionAsync(extension, WopiActionEnum.Edit);

        // Assert
        Assert.False(result, $"{extension} should not be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "pptx", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", XmlOos2016)]
    public async Task SupportedExtensionWithAction(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.SupportsActionAsync(extension, WopiActionEnum.Edit);

        // Assert
        Assert.True(result, $"{extension} should be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "PPTX", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "DOCX", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "PpTx", XmlOos2016)]
    public async Task CaseInsensitiveSupportedExtensionWithAction(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.SupportsActionAsync(extension, WopiActionEnum.Edit);

        // Assert
        Assert.True(result, $"{extension} should be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "html", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "txt", XmlOos2016)]
    public async Task NonSupportedExtensionCobalt(NetZoneEnum netZone, string extension, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.RequiresCobaltAsync(extension, WopiActionEnum.Edit);

        // Assert
        Assert.False(result, $"{extension} should not be supported!");
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "docx", XmlOwa2013, true)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", XmlOos2016, false)]
    public async Task SupportedExtensionCobalt(NetZoneEnum netZone, string extension, string fileName, bool expected)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.RequiresCobaltAsync(extension, WopiActionEnum.Edit);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", WopiActionEnum.Edit, "http://owaserver/x/_layouts/xlviewerinternal.aspx?edit=1&<ui=UI_LLCC&><rs=DC_LLCC&>", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", WopiActionEnum.Edit, "http://owaserver/we/wordeditorframe.aspx?<ui=UI_LLCC&><rs=DC_LLCC&><showpagestats=PERFSTATS&>", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "html", WopiActionEnum.Edit, null, XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "txt", WopiActionEnum.Edit, null, XmlOwa2013)]
    public async Task UrlTemplateTests(NetZoneEnum netZone, string extension, WopiActionEnum action, string? expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetUrlTemplateAsync(extension, action);

        // Assert
        Assert.Equal(expectedValue, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "XLSX", WopiActionEnum.Edit, "http://owaserver/x/_layouts/xlviewerinternal.aspx?edit=1&<ui=UI_LLCC&><rs=DC_LLCC&>", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "DOCX", WopiActionEnum.Edit, "http://owaserver/we/wordeditorframe.aspx?<ui=UI_LLCC&><rs=DC_LLCC&><showpagestats=PERFSTATS&>", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "XlSx", WopiActionEnum.Edit, "http://owaserver/x/_layouts/xlviewerinternal.aspx?edit=1&<ui=UI_LLCC&><rs=DC_LLCC&>", XmlOwa2013)]
    public async Task CaseInsensitiveExtensionTests(NetZoneEnum netZone, string extension, WopiActionEnum action, string? expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetUrlTemplateAsync(extension, action);

        // Assert
        Assert.Equal(expectedValue, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", "Excel", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", "Word", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "html", null, XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "txt", null, XmlOos2016)]
    public async Task AppNameTests(NetZoneEnum netZone, string extension, string? expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetApplicationNameAsync(extension);

        // Assert
        Assert.Equal(expectedValue, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "XLSX", "Excel", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "DOCX", "Word", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "XlSx", "Excel", XmlOos2016)]
    public async Task CaseInsensitiveAppNameTests(NetZoneEnum netZone, string extension, string? expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetApplicationNameAsync(extension);

        // Assert
        Assert.Equal(expectedValue, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", "http://owaserver/x/_layouts/resources/FavIcon_Excel.ico", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", "http://owaserver/wv/resources/1033/FavIcon_Word.ico", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "html", null, XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "txt", null, XmlOos2016)]
    public async Task FavIconTests(NetZoneEnum netZone, string extension, string? expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetApplicationFavIconAsync(extension);

        // Assert
        Assert.Equal(expectedValue is not null ? new Uri(expectedValue) : null, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", WopiActionEnum.Edit, "update", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", WopiActionEnum.Edit, "locks", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", WopiActionEnum.Edit, "cobalt", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "docx", WopiActionEnum.Edit, "update", XmlOos2016)]
    [InlineData(NetZoneEnum.InternalHttp, "one", WopiActionEnum.View, "containers", XmlOwa2013)]
    public async Task ActionRequirementsTests(NetZoneEnum netZone, string extension, WopiActionEnum action, string expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetActionRequirementsAsync(extension, action);

        // Assert
        Assert.Contains(expectedValue, result);
    }

    [Theory]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", WopiActionEnum.Edit, "http://owaserver/x/_layouts/xlviewerinternal.aspx?edit=1&<ui=UI_LLCC&><rs=DC_LLCC&>", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "one", WopiActionEnum.Edit, "locks", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", WopiActionEnum.Edit, "locks", XmlOwa2013)]
    [InlineData(NetZoneEnum.InternalHttp, "xlsx", WopiActionEnum.Edit, "cobalt", XmlOos2016)]
    public async Task ActionRequirementsNegativeTests(NetZoneEnum netZone, string extension, WopiActionEnum action, string expectedValue, string fileName)
    {
        // Arrange
        InitDiscoverer(fileName, netZone);

        // Act
        var result = await _wopiDiscoverer.GetActionRequirementsAsync(extension, action);

        // Assert
        Assert.DoesNotContain(expectedValue, result);
    }
}
