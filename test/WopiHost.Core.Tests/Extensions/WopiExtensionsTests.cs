using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using WopiHost.Abstractions;
using WopiHost.Core.Extensions;
using WopiHost.Core.Models;

namespace WopiHost.Core.Tests.Extensions;

public class WopiExtensionsTests
{
    [Fact]
    public async Task GetEncodedSha256_ReturnsBase64Checksum_WhenChecksumIsProvided()
    {
        // Arrange
        var mockFile = new Mock<IWopiFile>();
        var checksum = new byte[] { 1, 2, 3, 4, 5 };
        mockFile.Setup(f => f.Checksum).Returns(checksum);

        // Act
        var result = await mockFile.Object.GetEncodedSha256();

        // Assert
        Assert.Equal(Convert.ToBase64String(checksum), result);
    }

    [Fact]
    public async Task GetEncodedSha256_CalculatesChecksum_WhenChecksumIsNotProvided()
    {
        // Arrange
        var mockFile = new Mock<IWopiFile>();
        mockFile.Setup(f => f.Checksum).Returns((byte[]?)null);
        var stream = new MemoryStream([1, 2, 3, 4, 5]);
        mockFile.Setup(f => f.GetReadStream(It.IsAny<CancellationToken>())).ReturnsAsync(stream);

        // Act
        var result = await mockFile.Object.GetEncodedSha256();

        // Assert
        var expectedChecksum = SHA256.HashData([1, 2, 3, 4, 5]);
        Assert.Equal(Convert.ToBase64String(expectedChecksum), result);
    }

    [Fact]
    public async Task GetEncodedSha256_CalculatesChecksumsConcurrently()
    {
        // Arrange
        const int requestCount = 32;
        byte[] content = [1, 2, 3, 4, 5];
        var releaseReads = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var mockFile = new Mock<IWopiFile>();
        mockFile.Setup(f => f.Checksum).Returns((byte[]?)null);
        mockFile
            .Setup(f => f.GetReadStream(It.IsAny<CancellationToken>()))
            .Returns(() => Task.FromResult<Stream>(new GatedReadStream(content, releaseReads.Task)));

        // Act
        var hashTasks = Enumerable.Range(0, requestCount)
            .Select(_ => mockFile.Object.GetEncodedSha256())
            .ToArray();
        releaseReads.SetResult();
        var results = await Task.WhenAll(hashTasks);

        // Assert
        var expectedChecksum = Convert.ToBase64String(SHA256.HashData(content));
        Assert.All(results, result => Assert.Equal(expectedChecksum, result));
    }

    [Fact]
    public async Task GetWopiCheckFileInfo_ReturnsCorrectInfo()
    {
        // Arrange
        var mockFile = new Mock<IWopiFile>();
        mockFile.Setup(f => f.Name).Returns("test");
        mockFile.Setup(f => f.Owner).Returns("owner");
        mockFile.Setup(f => f.Extension).Returns("txt");
        mockFile.Setup(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        mockFile.Setup(f => f.Exists).Returns(true);
        mockFile.Setup(f => f.Length).Returns(12345);

        var capabilities = new WopiHostCapabilities
        {
            SupportsCoauth = true,
            SupportsFolders = true,
            SupportsLocks = true,
            SupportsGetLock = true,
            SupportsExtendedLockLength = true,
            SupportsEcosystem = true,
            SupportsGetFileWopiSrc = true,
            SupportedShareUrlTypes = ["ReadOnly", "ReadWrite"],
            SupportsScenarioLinks = true,
            SupportsSecureStore = true,
            SupportsUpdate = true,
            SupportsCobalt = true,
            SupportsRename = true,
            SupportsDeleteFile = true,
            SupportsUserInfo = true,
            SupportsFileCreation = true
        };
        var httpContext = new DefaultHttpContext()
        {
            ServiceScopeFactory = TestUtils.CreateServiceScope(),
        };

        // Act
        var result = await mockFile.Object.GetWopiCheckFileInfo(httpContext, capabilities, "userInfo text");

        // Assert
        Assert.Equal("owner", result.OwnerId);
        Assert.Equal("test.txt", result.BaseFileName);
        Assert.Equal(".txt", result.FileExtension);
        Assert.Equal(0, result.FileNameMaxLength);
        Assert.Equal(12345, result.Size);
        Assert.Equal("userInfo text", result.UserInfo);
        Assert.True(result.SupportsCoauth);
        Assert.True(result.SupportsFolders);
        Assert.True(result.SupportsLocks);
        Assert.True(result.SupportsGetLock);
        Assert.True(result.SupportsExtendedLockLength);
        Assert.True(result.SupportsEcosystem);
        Assert.True(result.SupportsGetFileWopiSrc);
        Assert.Equal(["ReadOnly", "ReadWrite"], result.SupportedShareUrlTypes);
        Assert.True(result.SupportsScenarioLinks);
        Assert.True(result.SupportsSecureStore);
        Assert.True(result.SupportsUpdate);
        Assert.True(result.SupportsCobalt);
        Assert.True(result.SupportsRename);
        Assert.True(result.SupportsDeleteFile);
        Assert.True(result.SupportsUserInfo);
        Assert.True(result.SupportsFileCreation);
        Assert.True(result.IsAnonymousUser);
    }

    [Fact]
    public async Task GetWopiCheckFileInfo_WithWritableStorageProvider_ReturnsCorrectInfo()
    {
        // Arrange
        var mockFile = new Mock<IWopiFile>();
        mockFile.Setup(f => f.Name).Returns("test");
        mockFile.Setup(f => f.Owner).Returns("owner");
        mockFile.Setup(f => f.Extension).Returns("txt");
        mockFile.Setup(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        mockFile.Setup(f => f.Exists).Returns(true);
        mockFile.Setup(f => f.Length).Returns(12345);

        var writableStorageProvider = new Mock<IWopiWritableStorageProvider>();
        writableStorageProvider.Setup(_ => _.FileNameMaxLength).Returns(13);
        var httpContext = new DefaultHttpContext()
        {
            ServiceScopeFactory = TestUtils.CreateServiceScope(writableStorageProvider.Object),
        };

        // Act
        var result = await mockFile.Object.GetWopiCheckFileInfo(httpContext);

        // Assert
        Assert.Equal(13, result.FileNameMaxLength);
    }

    [Fact]
    public async Task GetWopiCheckFileInfo_CallsOnCheckFileInfoEvent()
    {
        // Arrange
        var mockFile = new Mock<IWopiFile>();
        mockFile.Setup(f => f.Name).Returns("test");
        mockFile.Setup(f => f.Owner).Returns("owner");
        mockFile.Setup(f => f.Extension).Returns("txt");
        mockFile.Setup(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        mockFile.Setup(f => f.Exists).Returns(true);
        mockFile.Setup(f => f.Length).Returns(12345);
        var eventFired = false;
        var wopiHostOptions = Options.Create(new WopiHostOptions
        {
            StorageProviderAssemblyName = "test",
            ClientUrl = new Uri("http://localhost:5000"),
            OnCheckFileInfo = context => { eventFired = true; return Task.FromResult(context.CheckFileInfo); }
        });
        var httpContext = new DefaultHttpContext()
        {
            ServiceScopeFactory = TestUtils.CreateServiceScope<IOptions<WopiHostOptions>>(wopiHostOptions),
        };

        // Act
        var result = await mockFile.Object.GetWopiCheckFileInfo(httpContext);

        // Assert
        Assert.True(eventFired);
    }

    [Fact]
    public async Task GetWopiCheckFileInfo_WithAuthenticatedUser()
    {
        // Arrange
        var mockFile = new Mock<IWopiFile>();
        mockFile.Setup(f => f.Name).Returns("test");
        mockFile.Setup(f => f.Owner).Returns("owner");
        mockFile.Setup(f => f.Extension).Returns("txt");
        mockFile.Setup(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        mockFile.Setup(f => f.Exists).Returns(true);
        mockFile.Setup(f => f.Length).Returns(12345);
        var mockSecurityHandler = new Mock<IWopiSecurityHandler>();
        mockSecurityHandler
            .Setup(_ => _.GetUserPermissions(It.IsAny<ClaimsPrincipal>(), It.IsAny<IWopiFile>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(WopiUserPermissions.None);
        var httpContext = new DefaultHttpContext()
        {
            ServiceScopeFactory = TestUtils.CreateServiceScope(mockSecurityHandler.Object),
            User = new ClaimsPrincipal(
                new ClaimsIdentity(
                [
                    new(ClaimTypes.NameIdentifier, "userId"),
                    new(ClaimTypes.Name, "test")
                ], "test auth scheme")),
        };

        // Act
        var result = await mockFile.Object.GetWopiCheckFileInfo(httpContext);

        // Assert
        Assert.Equal("userId", result.UserId);
        Assert.Equal("userId", result.HostAuthenticationId);
        Assert.Equal("test", result.UserFriendlyName);
        Assert.Empty(result.UserPrincipalName);
        Assert.False(result.ReadOnly);
        Assert.False(result.RestrictedWebViewOnly);
        Assert.False(result.UserCanAttend);
        Assert.False(result.UserCanNotWriteRelative);
        Assert.False(result.UserCanPresent);
        Assert.False(result.UserCanRename);
        Assert.False(result.UserCanWrite);
        Assert.False(result.WebEditingDisabled);
        Assert.False(result.IsAnonymousUser);
    }

    [Fact]
    public async Task GetWopiCheckContainerInfo_CallsOnCheckContainerInfoEvent()
    {
        // Arrange
        var mockFolder = new Mock<IWopiFolder>();
        mockFolder.Setup(f => f.Name).Returns("test");
        var eventFired = false; var wopiHostOptions = Options.Create(new WopiHostOptions
        {
            StorageProviderAssemblyName = "test",
            ClientUrl = new Uri("http://localhost:5000"),
            OnCheckContainerInfo = context => { eventFired = true; return Task.FromResult(context.CheckContainerInfo); }
        });
        var httpContext = new DefaultHttpContext()
        {
            ServiceScopeFactory = TestUtils.CreateServiceScope<IOptions<WopiHostOptions>>(wopiHostOptions),
        };

        // Act
        var result = await mockFolder.Object.GetWopiCheckContainerInfo(httpContext);

        // Assert
        Assert.Equal("test", result.Name);
        Assert.True(eventFired);
    }

    private sealed class GatedReadStream(byte[] content, Task releaseReads) : Stream
    {
        private readonly MemoryStream inner = new(content, writable: false);
        private bool isFirstRead = true;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override async Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            await WaitForRelease();
            return await inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await WaitForRelease();
            return await inner.ReadAsync(buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }

        private async Task WaitForRelease()
        {
            if (isFirstRead)
            {
                isFirstRead = false;
                await releaseReads;
            }
        }
    }
}
