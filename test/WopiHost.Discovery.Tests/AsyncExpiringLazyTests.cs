using System.Reflection;

namespace WopiHost.Discovery.Tests;

public class AsyncExpiringLazyTests
{
    private static AsyncExpiringLazy<string> CreateSut(
        Func<TemporaryValue<string>, Task<TemporaryValue<string>>> provider)
        => new(provider);

    [Fact]
    public void Constructor_NullProvider_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AsyncExpiringLazy<string>(valueProvider: null!));
    }

    [Fact]
    public async Task IsValueCreated_BeforeFirstValue_ReturnsFalse()
    {
        using var sut = CreateSut(_ => Task.FromResult(new TemporaryValue<string>
        {
            Result = "x",
            ValidUntil = DateTimeOffset.UtcNow.AddHours(1),
        }));

        Assert.False(await sut.IsValueCreated());
    }

    [Fact]
    public async Task IsValueCreated_AfterFirstValue_ReturnsTrue()
    {
        using var sut = CreateSut(_ => Task.FromResult(new TemporaryValue<string>
        {
            Result = "x",
            ValidUntil = DateTimeOffset.UtcNow.AddHours(1),
        }));

        await sut.Value();

        Assert.True(await sut.IsValueCreated());
    }

    [Fact]
    public async Task Value_FirstCall_InvokesProvider()
    {
        var calls = 0;
        using var sut = CreateSut(_ =>
        {
            calls++;
            return Task.FromResult(new TemporaryValue<string>
            {
                Result = "hello",
                ValidUntil = DateTimeOffset.UtcNow.AddHours(1),
            });
        });

        var result = await sut.Value();

        Assert.Equal("hello", result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Value_SecondCallWithinValidity_ReturnsCached()
    {
        var calls = 0;
        using var sut = CreateSut(_ =>
        {
            calls++;
            return Task.FromResult(new TemporaryValue<string>
            {
                Result = "hello",
                ValidUntil = DateTimeOffset.UtcNow.AddHours(1),
            });
        });

        await sut.Value();
        await sut.Value();

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Value_AfterExpiry_RefetchesValue()
    {
        var calls = 0;
        using var sut = CreateSut(_ =>
        {
            calls++;
            return Task.FromResult(new TemporaryValue<string>
            {
                Result = $"call-{calls}",
                ValidUntil = DateTimeOffset.UtcNow.AddMilliseconds(-1),
            });
        });

        await sut.Value();
        var second = await sut.Value();

        Assert.Equal(2, calls);
        Assert.Equal("call-2", second);
    }

    [Fact]
    public async Task Value_ConcurrentFirstTimeCallers_InvokeProviderExactlyOnce()
    {
        var calls = 0;
        using var sut = CreateSut(_ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(ValidValue("hello"));
        });
        var results = await ReadQueued(sut);

        Assert.Equal(1, calls);
        Assert.All(results, r => Assert.Equal("hello", r));
    }

    [Fact]
    public async Task Value_TwoInstances_DoNotShareLock()
    {
        var enteredA = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gateA = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        using var sutA = CreateSut(async _ =>
        {
            enteredA.SetResult(true);
            await gateA.Task;
            return ValidValue("A");
        });
        using var sutB = CreateSut(_ => Task.FromResult(ValidValue("B")));

        var taskA = sutA.Value();
        await enteredA.Task.WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            Assert.Equal("B", await sutB.Value().WaitAsync(TimeSpan.FromSeconds(5)));
        }
        finally
        {
            gateA.SetResult(true);
            await taskA.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Assert.Equal("A", await taskA.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task Value_ConcurrentExpiredCallers_InvokeProviderExactlyOnce()
    {
        var calls = 0;
        using var sut = CreateSut(_ => Task.FromResult(new TemporaryValue<string>
        {
            Result = $"call-{++calls}",
            ValidUntil = calls == 1 ? DateTimeOffset.MinValue : DateTimeOffset.UtcNow.AddHours(1),
        }));
        await sut.Value();

        var results = await ReadQueued(sut);

        Assert.Equal(2, calls);
        Assert.All(results, value => Assert.Equal("call-2", value));
    }

    [Fact]
    public async Task Invalidate_DuringFetch_NextReadRefetches()
    {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        using var sut = CreateSut(async _ =>
        {
            calls++;
            await release.Task;
            return ValidValue($"call-{calls}");
        });
        var read = sut.Value();
        Assert.Equal(1, calls);
        var invalidation = sut.Invalidate();
        Assert.False(invalidation.IsCompleted);
        release.SetResult(true);
        await read.WaitAsync(TimeSpan.FromSeconds(5));
        await invalidation.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(await sut.IsValueCreated());
        Assert.Equal("call-2", await sut.Value());
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Value_FailedFetch_AllowsNextCallerToRetry()
    {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        using var sut = CreateSut(async _ =>
        {
            if (++calls == 1)
            {
                await release.Task;
                throw new InvalidOperationException("offline");
            }
            return ValidValue("recovered");
        });
        var first = sut.Value();
        var retry = sut.Value();
        release.SetResult(true);

        await Assert.ThrowsAsync<InvalidOperationException>(() => first.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("recovered", await retry.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(await sut.IsValueCreated());
        Assert.Equal("recovered", await sut.Value());
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task IsValueCreated_DuringFetch_ObservesPublishedValue()
    {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var sut = CreateSut(async _ =>
        {
            await release.Task;
            return ValidValue("hello");
        });
        var read = sut.Value();
        var created = sut.IsValueCreated();
        Assert.False(created.IsCompleted);
        release.SetResult(true);

        await read.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(await created.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task Dispose_AfterUse_IsRepeatable()
    {
        using var sut = CreateSut(_ => Task.FromResult(ValidValue("hello")));
        await sut.Value();

        sut.Dispose();
        sut.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => sut.Value());
    }

    private static TemporaryValue<string> ValidValue(string value) => new()
    {
        Result = value,
        ValidUntil = DateTimeOffset.UtcNow.AddHours(1),
    };

    private static async Task<string[]> ReadQueued(AsyncExpiringLazy<string> sut)
    {
        // Queue all cache checks before fetching, preserving the reproduced interleaving.
        var field = typeof(AsyncExpiringLazy<string>).GetField("_syncLock", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var gate = (SemaphoreSlim)field.GetValue(sut)!;
        await gate.WaitAsync();
        Task<string>[] reads;
        try
        {
            reads = Enumerable.Range(0, 8).Select(_ => sut.Value()).ToArray();
        }
        finally
        {
            gate.Release();
        }
        return await Task.WhenAll(reads).WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Invalidate_ClearsCachedValue()
    {
        var calls = 0;
        using var sut = CreateSut(_ =>
        {
            calls++;
            return Task.FromResult(new TemporaryValue<string>
            {
                Result = "hello",
                ValidUntil = DateTimeOffset.UtcNow.AddHours(1),
            });
        });

        await sut.Value();
        await sut.Invalidate();

        Assert.False(await sut.IsValueCreated());

        await sut.Value();
        Assert.Equal(2, calls);
    }
}
