using System.Globalization;
using System.Net.Mime;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using WopiHost.Abstractions;
using WopiHost.Core.Controllers;
using WopiHost.Core.Infrastructure;
using WopiHost.Core.Models;
using WopiHost.Core.Results;

namespace WopiHost.Core.Tests.Controllers;

public class FilesControllerTests
{
    private readonly Mock<IWopiStorageProvider> storageProviderMock;
    private readonly Mock<IWopiWritableStorageProvider> writableStorageProviderMock;
    private readonly Mock<IWopiSecurityHandler> securityHandlerMock;
    private readonly Mock<IOptions<WopiHostOptions>> wopiHostOptionsMock;
    private readonly IMemoryCache memoryCache;
    private readonly Mock<IWopiLockProvider> lockProviderMock;
    private FilesController controller;

    public FilesControllerTests()
    {
        storageProviderMock = new Mock<IWopiStorageProvider>();
        writableStorageProviderMock = new Mock<IWopiWritableStorageProvider>();
        securityHandlerMock = new Mock<IWopiSecurityHandler>();
        wopiHostOptionsMock = new Mock<IOptions<WopiHostOptions>>();
        wopiHostOptionsMock
            .SetupGet(o => o.Value)
            .Returns(new WopiHostOptions()
            {
                StorageProviderAssemblyName = "test",
                LockProviderAssemblyName = "test",
                OnCheckFileInfo = o => Task.FromResult(o.CheckFileInfo),
                ClientUrl = new Uri("http://localhost:5000"),
            });
        memoryCache = new MemoryCache(new MemoryCacheOptions());
        lockProviderMock = new Mock<IWopiLockProvider>();

        controller = new FilesController(
            storageProviderMock.Object,
            memoryCache,
            writableStorageProviderMock.Object,
            lockProviderMock.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
    }

    public static TheoryData<string> OptionalMetadataFields => new()
    {
        "ClientUrl", "FileEmbedCommandUrl", "HostAuthenticationId", "HostEmbeddedEditUrl", "HostNotes", "HostRestUrl",
        "IrmPolicyDescription", "IrmPolicyTitle", "PresenceProvider", "PresenceUserId", "TenantId", "TimeZone", "UserPrincipalName",
        "BreadcrumbBrandName", "BreadcrumbBrandUrl", "BreadcrumbDocName", "BreadcrumbFolderName", "BreadcrumbFolderUrl",
        "CloseUrl", "DownloadUrl", "FileSharingUrl", "FileUrl", "FileVersionUrl", "HostEditUrl", "HostEmbeddedViewUrl",
        "HostViewUrl", "SignInUrl", "SignoutUrl",
    };

    [Theory]
    [MemberData(nameof(OptionalMetadataFields))]
    public async Task CheckFileInfo_EmitsConfiguredMetadata(string propertyName)
    {
        using var unset = await ReadCheckFileInfo(info => info);
        Assert.False(unset.RootElement.TryGetProperty(propertyName, out _));

        var property = typeof(WopiCheckFileInfo).GetProperty(propertyName)!;
        object value = property.PropertyType == typeof(Uri) ? new Uri("https://host.example/metadata") : "configured";
        using var populated = await ReadCheckFileInfo(info =>
        {
            property.SetValue(info, value);
            return info;
        });
        Assert.Equal(value.ToString(), populated.RootElement.GetProperty(propertyName).GetString());

        using var cleared = await ReadCheckFileInfo(info =>
        {
            property.SetValue(info, null);
            return info;
        });
        Assert.False(cleared.RootElement.TryGetProperty(propertyName, out _));
    }

    [Theory]
    [InlineData("BreadcrumbDocUrl")]
    [InlineData("HostName")]
    [InlineData("PrivacyUrl")]
    public async Task CheckFileInfo_OmitsDeprecatedMetadata(string propertyName)
    {
        using var unset = await ReadCheckFileInfo(info => info);
        Assert.False(unset.RootElement.TryGetProperty(propertyName, out _));
        var property = typeof(WopiCheckFileInfo).GetProperty(propertyName)!;
        using var populated = await ReadCheckFileInfo(info =>
        {
            property.SetValue(info, property.PropertyType == typeof(Uri) ? new Uri("https://host.example/deprecated") : "deprecated");
            return info;
        });

        Assert.False(populated.RootElement.TryGetProperty(propertyName, out _));
    }

    [Fact]
    public async Task CheckFileInfo_PreservesPlatformCapabilityProfile()
    {
        securityHandlerMock.Setup(s => s.GetUserPermissions(It.IsAny<ClaimsPrincipal>(), It.IsAny<IWopiFile>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(WopiUserPermissions.UserCanWrite | WopiUserPermissions.UserCanAttend |
                WopiUserPermissions.UserCanPresent | WopiUserPermissions.UserCanNotWriteRelative);
        using var result = await ReadCheckFileInfo(info =>
        {
            info.SupportsCoauth = true;
            info.SupportsEcosystem = true;
            info.SupportsGetFileWopiSrc = true;
            info.SupportsRename = false;
            info.SupportsDeleteFile = false;
            info.SupportsExtendedLockLength = true;
            info.SupportsUserInfo = true;
            info.SupportsUpdate = true;
            info.SupportsContainers = false;
            info.SupportsFolders = false;
            info.SupportsFileCreation = false;
            info.SupportsScenarioLinks = false;
            info.SupportsSecureStore = false;
            return info;
        }, authenticated: true);

        foreach (var name in new[] { "SupportsLocks", "SupportsGetLock", "SupportsExtendedLockLength", "SupportsUpdate",
                     "SupportsEcosystem", "SupportsUserInfo", "UserCanNotWriteRelative", "UserCanWrite" })
        {
            Assert.True(result.RootElement.GetProperty(name).GetBoolean(), name);
        }
        foreach (var name in new[] { "SupportsCobalt", "SupportsRename", "SupportsDeleteFile", "SupportsFolders", "SupportsContainers", "UserCanRename" })
        {
            Assert.False(result.RootElement.GetProperty(name).GetBoolean(), name);
        }
        foreach (var name in new[] { "SupportsCoauth", "SupportsGetFileWopiSrc", "SupportsFileCreation", "SupportsScenarioLinks",
                     "SupportsSecureStore", "CloseButtonClosesWindow" })
        {
            Assert.False(result.RootElement.TryGetProperty(name, out _), name);
        }
        Assert.Equal(0, result.RootElement.GetProperty("SupportedShareUrlTypes").GetArrayLength());
    }

    [Theory]
    [InlineData("SupportsCoauth")]
    [InlineData("SupportsGetFileWopiSrc")]
    [InlineData("SupportsFileCreation")]
    [InlineData("SupportsScenarioLinks")]
    [InlineData("SupportsSecureStore")]
    [InlineData("CloseButtonClosesWindow")]
    public async Task CheckFileInfo_DoesNotActivateHiddenCapabilities(string propertyName)
    {
        using var result = await ReadCheckFileInfo(info =>
        {
            typeof(WopiCheckFileInfo).GetProperty(propertyName)!.SetValue(info, true);
            return info;
        });

        Assert.False(result.RootElement.TryGetProperty(propertyName, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("user@example.com")]
    public async Task CheckFileInfo_PreservesExplicitUserPrincipalName(string? upn)
    {
        using var result = await ReadCheckFileInfo(info =>
        {
            info.UserPrincipalName = upn;
            return info;
        }, authenticated: true);

        if (upn is null)
        {
            Assert.False(result.RootElement.TryGetProperty("UserPrincipalName", out _));
        }
        else
        {
            Assert.Equal(upn, result.RootElement.GetProperty("UserPrincipalName").GetString());
        }
    }

    [Fact]
    public async Task CheckFileInfo_EmitsDerivedMetadata()
    {
        using var result = await ReadCheckFileInfo(info => new ExtendedCheckFileInfo
        {
            BaseFileName = info.BaseFileName, OwnerId = info.OwnerId, UserId = info.UserId, Version = info.Version,
            UserPrincipalName = "user@example.com",
        });

        Assert.Equal("extension", result.RootElement.GetProperty("CustomMetadata").GetString());
        Assert.Equal("user@example.com", result.RootElement.GetProperty("UserPrincipalName").GetString());
    }

    private async Task<JsonDocument> ReadCheckFileInfo(Func<WopiCheckFileInfo, WopiCheckFileInfo> callback, bool authenticated = false)
    {
        var file = new Mock<IWopiFile>();
        file.SetupGet(f => f.Name).Returns("report");
        file.SetupGet(f => f.Extension).Returns("docx");
        file.SetupGet(f => f.Owner).Returns("owner");
        file.SetupGet(f => f.Checksum).Returns([1, 2, 3]);
        storageProviderMock.Setup(s => s.GetWopiResource<IWopiFile>("metadata", It.IsAny<CancellationToken>())).ReturnsAsync(file.Object);
        wopiHostOptionsMock.Object.Value.OnCheckFileInfo = context => Task.FromResult(callback(context.CheckFileInfo));
        using var services = new ServiceCollection()
            .AddSingleton(securityHandlerMock.Object)
            .AddSingleton(wopiHostOptionsMock.Object)
            .BuildServiceProvider();
        controller.HttpContext.RequestServices = services;
        controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "user")], authenticated ? "test" : null));
        var result = Assert.IsType<ContentResult>(await controller.CheckFileInfo("metadata"));
        Assert.Equal(StatusCodes.Status200OK, result.StatusCode);
        return JsonDocument.Parse(result.Content!);
    }

    private sealed class ExtendedCheckFileInfo : WopiCheckFileInfo
    {
        public string CustomMetadata => "extension";
    }

    [Fact]
    public async Task GetCheckFileInfo_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        var fileId = "testFileId";
        storageProviderMock.Setup(s => s.GetWopiResource<IWopiFile>(fileId, It.IsAny<CancellationToken>())).ReturnsAsync(() => null);

        // Act
        var result = await controller.CheckFileInfo(fileId);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetCheckFileInfo_Success_ReturnsFileInfoForAnonymous()
    {
        // Arrange
        var fileId = "testFileId";
        var fileMock = new Mock<IWopiFile>();
        fileMock.SetupGet(f => f.Owner).Returns("ownerId");
        fileMock.SetupGet(f => f.Version).Returns("1.0");
        fileMock.SetupGet(f => f.Name).Returns("test");
        fileMock.SetupGet(f => f.Extension).Returns("txt");
        fileMock.SetupGet(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        fileMock.SetupGet(f => f.Length).Returns(1024);
        fileMock.Setup(f => f.GetReadStream(It.IsAny<CancellationToken>())).ReturnsAsync(new System.IO.MemoryStream());
        storageProviderMock
            .Setup(s => s.GetWopiResource<IWopiFile>(fileId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => fileMock.Object);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
            {
                ServiceScopeFactory = TestUtils.CreateServiceScope(securityHandlerMock.Object),
                User = new ClaimsPrincipal(
                    new ClaimsIdentity(
                    [
                        new(ClaimTypes.NameIdentifier, "userId"),
                        new(ClaimTypes.Name, "test")
                    ])),
            }
        };

        // Act
        var result = await controller.CheckFileInfo(fileId);

        // Assert
        var contentResult = Assert.IsType<ContentResult>(result);
        Assert.NotNull(contentResult.Content);
        Assert.Equal(StatusCodes.Status200OK, contentResult.StatusCode);
        Assert.Equal(MediaTypeNames.Application.Json, contentResult.ContentType);
        var resultContent = JsonSerializer.Deserialize<WopiCheckFileInfo>(contentResult.Content);
        Assert.NotNull(resultContent);
        Assert.Equal(fileMock.Object.Owner, resultContent.OwnerId);
        Assert.Equal(fileMock.Object.Version, resultContent.Version);
        Assert.Equal("." + fileMock.Object.Extension, resultContent.FileExtension);
        Assert.Equal(fileMock.Object.Name + "." + fileMock.Object.Extension, resultContent.BaseFileName);
        Assert.Equal(fileMock.Object.LastWriteTimeUtc.ToString("o", CultureInfo.InvariantCulture), resultContent.LastModifiedTime);
        Assert.True(resultContent.IsAnonymousUser);
    }

    [Fact]
    public async Task GetCheckFileInfo_Success_ReturnsFileInfoWithAuthenticatedUser()
    {
        // Arrange
        var fileId = "testFileId";
        var fileMock = new Mock<IWopiFile>();
        fileMock.SetupGet(f => f.Owner).Returns("ownerId");
        fileMock.SetupGet(f => f.Version).Returns("1.0");
        fileMock.SetupGet(f => f.Name).Returns("test");
        fileMock.SetupGet(f => f.Extension).Returns("txt");
        fileMock.SetupGet(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        fileMock.SetupGet(f => f.Length).Returns(1024);
        fileMock.Setup(f => f.GetReadStream(It.IsAny<CancellationToken>())).ReturnsAsync(new System.IO.MemoryStream());

        storageProviderMock
            .Setup(s => s.GetWopiResource<IWopiFile>(fileId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => fileMock.Object);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
            {
                ServiceScopeFactory = TestUtils.CreateServiceScope(securityHandlerMock.Object),
                User = new ClaimsPrincipal(
                    new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, "nameId"),
                        new Claim(ClaimTypes.Name, "testUser")
                    ], "TestAuthentication"))
            }
        };

        // Act
        var result = await controller.CheckFileInfo(fileId);

        // Assert
        var contentResult = Assert.IsType<ContentResult>(result);
        Assert.NotNull(contentResult.Content);
        Assert.Equal(StatusCodes.Status200OK, contentResult.StatusCode);
        Assert.Equal(MediaTypeNames.Application.Json, contentResult.ContentType);
        var resultContent = JsonSerializer.Deserialize<WopiCheckFileInfo>(contentResult.Content);
        Assert.NotNull(resultContent);
        Assert.Equal(fileMock.Object.Owner, resultContent.OwnerId);
        Assert.Equal(fileMock.Object.Version, resultContent.Version);
        Assert.Equal("." + fileMock.Object.Extension, resultContent.FileExtension);
        Assert.Equal(fileMock.Object.Name + "." + fileMock.Object.Extension, resultContent.BaseFileName);
        Assert.Equal(fileMock.Object.LastWriteTimeUtc.ToString("o", CultureInfo.InvariantCulture), resultContent.LastModifiedTime);
        Assert.False(resultContent.IsAnonymousUser);
        Assert.Equal("nameId", resultContent.UserId);
        Assert.Equal("testUser", resultContent.UserFriendlyName);
    }

    [Fact]
    public async Task CheckFileInfo_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        storageProviderMock.Setup(sp => sp.GetWopiResource<IWopiFile>(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(() => null);

        // Act
        var result = await controller.CheckFileInfo("file_id");

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetFile_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        storageProviderMock.Setup(sp => sp.GetWopiResource<IWopiFile>(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(() => null);

        // Act
        var result = await controller.GetFile("file_id");

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetEcosystem_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        storageProviderMock.Setup(sp => sp.GetWopiResource<IWopiFile>(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(() => null);

        // Act
        var result = await controller.GetEcosystem("file_id");

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task EnumerateAncestors_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        storageProviderMock.Setup(sp => sp.GetWopiResource<IWopiFile>(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(() => null);

        // Act
        var result = await controller.EnumerateAncestors("file_id");

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task PutUserInfo_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        storageProviderMock.Setup(sp => sp.GetWopiResource<IWopiFile>(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(() => null);

        // Act
        var result = await controller.PutUserInfo("file_id", "user_info");

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task PutUserInfo_Success()
    {
        // Arrange
        var fileId = "testFileId";
        var fileMock = new Mock<IWopiFile>();
        fileMock.SetupGet(f => f.Owner).Returns("ownerId");
        fileMock.SetupGet(f => f.Version).Returns("1.0");
        fileMock.SetupGet(f => f.Name).Returns("test");
        fileMock.SetupGet(f => f.Extension).Returns("txt");
        fileMock.SetupGet(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        fileMock.SetupGet(f => f.Length).Returns(1024);
        fileMock.Setup(f => f.GetReadStream(It.IsAny<CancellationToken>())).ReturnsAsync(new System.IO.MemoryStream());

        storageProviderMock
            .Setup(s => s.GetWopiResource<IWopiFile>(fileId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => fileMock.Object);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
            {
                User = new ClaimsPrincipal(
                    new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, "nameId"),
                        new Claim(ClaimTypes.Name, "testUser")
                    ], "TestAuthentication"))
            }
        };

        // Act
        var result = await controller.PutUserInfo(fileId, "custom user info");

        // Assert
        Assert.IsType<OkResult>(result);
        Assert.Equal("custom user info", memoryCache.Get("UserInfo-nameId"));
    }

    [Fact]
    public async Task DeleteFile_NoWritableStorageProvider()
    {
        // Arrange
        controller = new FilesController(
                    storageProviderMock.Object,
                    memoryCache);
        // Act
        var result = await controller.DeleteFile("file_id");
        // Assert
        Assert.IsType<NotImplementedResult>(result);
    }

    [Fact]
    public async Task DeleteFile_FileNotFound_ReturnsNotFound()
    {
        // Arrange
        storageProviderMock.Setup(sp => sp.GetWopiResource<IWopiFile>(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(() => null);
        // Act
        var result = await controller.DeleteFile("file_id");
        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteFile_FileIsLocked_ReturnsConflict()
    {
        // Arrange
        var fileId = "testFileId";
        var fileMock = new Mock<IWopiFile>();
        fileMock.SetupGet(f => f.Owner).Returns("ownerId");
        fileMock.SetupGet(f => f.Version).Returns("1.0");
        fileMock.SetupGet(f => f.Name).Returns("test");
        fileMock.SetupGet(f => f.Extension).Returns("txt");
        fileMock.SetupGet(f => f.LastWriteTimeUtc).Returns(DateTime.UtcNow);
        fileMock.SetupGet(f => f.Length).Returns(1024);
        fileMock.Setup(f => f.GetReadStream(It.IsAny<CancellationToken>())).ReturnsAsync(new System.IO.MemoryStream());

        storageProviderMock
            .Setup(s => s.GetWopiResource<IWopiFile>(fileId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => fileMock.Object);
        var wopiLockInfo = new WopiLockInfo() { LockId = "lockId", FileId = fileId };
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out wopiLockInfo)).Returns(true);

        // Act
        var result = await controller.DeleteFile(fileId);

        // Assert
        Assert.IsType<LockMismatchResult>(result);
    }

    // Helper method to set up a simple file mock
    private void SetupFileMock(string fileId, string version = "1.0")
    {
        var fileMock = new Mock<IWopiFile>();
        fileMock.SetupGet(f => f.Version).Returns(version);
        
        storageProviderMock
            .Setup(s => s.GetWopiResource<IWopiFile>(fileId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(fileMock.Object);
    }

    [Fact]
    public async Task ProcessLock_LockingNotSupported_ReturnsLockMismatchResult()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        controller = new FilesController(
            storageProviderMock.Object,
            memoryCache)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        var wopiOverrideHeader = WopiFileOperations.Lock;

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader);

        // Assert
        var lockMismatchResult = Assert.IsType<LockMismatchResult>(result);
        Assert.Equal("Locking is not supported", lockMismatchResult.Reason);
    }

    [Fact]
    public async Task ProcessLock_GetLock_ReturnsOkResultWithLockHeader()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        var wopiOverrideHeader = WopiFileOperations.GetLock;
        var lockInfo = new WopiLockInfo { LockId = "existing-lock-id", FileId = fileId };
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out lockInfo)).Returns(true);

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader);

        // Assert
        Assert.IsType<OkResult>(result);
        Assert.Equal("existing-lock-id", controller.Response.Headers[WopiHeaders.LOCK]);
    }

    [Fact]
    public async Task ProcessLock_GetLock_NoLockInfo_ReturnsLockMismatchResult()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        var wopiOverrideHeader = WopiFileOperations.GetLock;
        WopiLockInfo? lockInfo = null;
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out lockInfo)).Returns(true);

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader);

        // Assert
        var lockMismatchResult = Assert.IsType<LockMismatchResult>(result);
        Assert.Equal("Missing existing lock", lockMismatchResult.Reason);
    }

    [Fact]
    public async Task ProcessLock_GetLock_Expired_ReturnsOkResultWithLockHeader()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        var wopiOverrideHeader = WopiFileOperations.GetLock;
        var lockInfo = new WopiLockInfo { LockId = "existing-lock-id", FileId = fileId, DateCreated = DateTimeOffset.MinValue };
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out lockInfo)).Returns(false);

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader);

        // Assert
        Assert.IsType<OkResult>(result);
        Assert.Equal(WopiHeaders.EMPTY_LOCK_VALUE, controller.Response.Headers[WopiHeaders.LOCK]);
    }

    [Fact]
    public async Task ProcessLock_LockWithoutOldLockIdentifier_ReturnsOkResult()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        var wopiOverrideHeader = WopiFileOperations.Lock;
        var newLockIdentifier = "new-lock-id";
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out It.Ref<WopiLockInfo?>.IsAny)).Returns(false);
        lockProviderMock.Setup(x => x.AddLock(fileId, newLockIdentifier)).Returns(new WopiLockInfo { LockId = newLockIdentifier, FileId = fileId });

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader, newLockIdentifier: newLockIdentifier);

        // Assert
        Assert.IsType<OkResult>(result);
    }

    [Fact]
    public async Task ProcessLock_Unlock_ReturnsOkResult()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        var wopiOverrideHeader = WopiFileOperations.Unlock;
        var newLockIdentifier = "existing-lock-id";
        var lockInfo = new WopiLockInfo { LockId = newLockIdentifier, FileId = fileId };
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out lockInfo)).Returns(true);
        lockProviderMock.Setup(x => x.RemoveLock(fileId)).Returns(true);

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader, newLockIdentifier: newLockIdentifier);

        // Assert
        Assert.IsType<OkResult>(result);
    }

    [Fact]
    public async Task ProcessLock_RefreshLock_ReturnsOkResult()
    {
        // Arrange
        var fileId = "test-file-id";
        SetupFileMock(fileId);
            
        var wopiOverrideHeader = WopiFileOperations.RefreshLock;
        var newLockIdentifier = "existing-lock-id";
        var lockInfo = new WopiLockInfo { LockId = newLockIdentifier, FileId = fileId };
        lockProviderMock.Setup(x => x.TryGetLock(fileId, out lockInfo)).Returns(true);
        lockProviderMock.Setup(x => x.RefreshLock(fileId, null)).Returns(true);

        // Act
        var result = await controller.ProcessLock(fileId, wopiOverrideHeader, newLockIdentifier: newLockIdentifier);

        // Assert
        Assert.IsType<OkResult>(result);
    }
}
