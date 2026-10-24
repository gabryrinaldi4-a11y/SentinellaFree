namespace Sentinella.Core;

/// <summary>A versioned local backup. Complete describes capture coverage, not protection from ransomware or later tampering.</summary>
public sealed record SnapshotInfo(string Id, string Source, DateTimeOffset CreatedAt,
    int FileCount, long TotalBytes, bool Complete, List<string> Errors);
