namespace Sentinella.Core;

public sealed record ContinuousSettings(bool Enabled, List<string> Folders, bool AutoUpdateSignatures = false, bool ObserveProcesses = true, int UpdateHours = 6);
public sealed record ProtectionAlert(DateTimeOffset Time, string Severity, string Kind, string Subject, string Detail);
public sealed record ContinuousSnapshot(DateTimeOffset StartedAt, DateTimeOffset Heartbeat, int ProcessId, string State, long Scanned, long Detections, long Incomplete, int Pending, DateTimeOffset? SignaturesUpdated, List<ProtectionAlert> Alerts, string? Error);
