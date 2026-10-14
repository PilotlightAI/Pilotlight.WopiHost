using Microsoft.Extensions.Logging;
using WopiHost.Core.Security.Authentication;

namespace WopiHost.Core.Tests.Security.Authentication;

/// <summary>
/// Records every log call with its structured values, so tests can assert on what was (and was not) logged.
/// </summary>
internal class CapturingLogger : ILogger
{
    public sealed record Entry(LogLevel Level, string Message, IReadOnlyDictionary<string, object?> Values, Exception? Exception);

    public List<Entry> Entries { get; } = [];

    // The framework's own authentication log lines are captured too; these are the diagnostics lines alone.
    public IEnumerable<Entry> PresenceLines => Entries.Where(e =>
        e.Values.TryGetValue("{OriginalFormat}", out var format) &&
        Equals(format, WopiAuthenticationDiagnostics.MESSAGE_TEMPLATE));

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var values = (state as IEnumerable<KeyValuePair<string, object?>> ?? [])
            .ToDictionary(kv => kv.Key, kv => kv.Value);
        Entries.Add(new Entry(logLevel, formatter(state, exception), values, exception));
    }
}

internal sealed class CapturingLogger<T> : CapturingLogger, ILogger<T>;
