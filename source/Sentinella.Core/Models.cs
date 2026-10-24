namespace Sentinella.Core;

public record Finding(string Path, string Sha256, string Verdict, string Detail);
public record ScanReport(DateTimeOffset StartedAt, DateTimeOffset FinishedAt,
    int FilesScanned, int FilesSkipped, List<Finding> Findings, List<string> Errors);
public record QuarantineEntry(string Id, string OriginalPath, string Sha256,
    string Name, DateTimeOffset CreatedAt);
