namespace Sentinella.Core;

public sealed record ClamStatus(bool EngineAvailable, string EngineVersion, bool DatabaseAvailable,
    bool OfficialDatabasesPresent, long SignatureCount, DateTimeOffset? DatabaseUpdatedAt,
    List<string> DatabaseFiles, string Detail);
public sealed record ClamDetection(string Path, string Signature, bool IsHeuristicWarning);
public sealed record ClamScanReport(DateTimeOffset StartedAt, DateTimeOffset FinishedAt, string Engine,
    string Target, int ExitCode, string Verdict, bool IsComplete, int ScannedFiles,
    List<ClamDetection> Detections, List<string> Warnings, string Output, string StandardError);
public sealed record EngineCommandResult(int ExitCode, string Output, string StandardError, bool OutputTruncated);
