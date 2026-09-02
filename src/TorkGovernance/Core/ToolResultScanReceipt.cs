using System.Text.Json.Serialization;

namespace TorkGovernance.Core;

/// <summary>Counts by type for one finding kind. Injection type keys keep their "heuristic:" prefix.</summary>
public sealed class ToolResultScanFindingCounts
{
    [JsonPropertyName("injection")]
    public required IReadOnlyDictionary<string, int> Injection { get; init; }

    [JsonPropertyName("pii")]
    public required IReadOnlyDictionary<string, int> Pii { get; init; }
}

/// <summary>Total match count per kind.</summary>
public sealed class ToolResultScanTotals
{
    [JsonPropertyName("injection")]
    public required int Injection { get; init; }

    [JsonPropertyName("pii")]
    public required int Pii { get; init; }
}

/// <summary>
/// The tool_result_scan block recorded on the receipt.
///
/// snake_case, keys emitted in ALPHABETICAL order (guaranteed here simply by
/// declaring the properties in alphabetical order -- System.Text.Json
/// serializes properties in declaration order by default, the same
/// discipline the Go port relies on for its struct field order), optional
/// keys OMITTED entirely rather than emitted null (JsonIgnoreCondition.
/// WhenWritingNull), matching the JS SDK's TORK-DNA-v2 canonical-form
/// discipline: every SDK that mirrors this must produce a byte-identical
/// block for the same scan.
///
/// It carries COUNTS ONLY. No payload, no matched substring, no location
/// path, no tool argument ever appears here.
/// </summary>
public sealed class ToolResultScanReceiptBlock
{
    /// <summary>Always "client". This scan ran in the caller's process; Tork did not execute it.</summary>
    [JsonPropertyName("attested_by")]
    public string AttestedBy { get; init; } = "client";

    [JsonPropertyName("blocked")]
    public required bool Blocked { get; init; }

    /// <summary>Always "edge" -- the capture_mode this SDK's client-side work is recorded under.</summary>
    [JsonPropertyName("capture_mode")]
    public string CaptureMode { get; init; } = "edge";

    [JsonPropertyName("findings")]
    public required ToolResultScanFindingCounts Findings { get; init; }

    /// <summary>Identifier of the injection ruleset that produced the injection counts.</summary>
    [JsonPropertyName("injection_ruleset")]
    public required string InjectionRuleset { get; init; }

    /// <summary>Present only when blocked.</summary>
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; init; }

    [JsonPropertyName("sdk_language")]
    public string SdkLanguage { get; init; } = "csharp";

    [JsonPropertyName("sdk_version")]
    public required string SdkVersion { get; init; }

    /// <summary>Present only when the caller supplied one.</summary>
    [JsonPropertyName("server_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServerUri { get; init; }

    [JsonPropertyName("tool_name")]
    public required string ToolName { get; init; }

    [JsonPropertyName("totals")]
    public required ToolResultScanTotals Totals { get; init; }
}

public static class ToolResultScanReceiptBuilder
{
    private static IReadOnlyDictionary<string, int> CountsByType(
        IReadOnlyList<ToolResultFinding> findings,
        ToolResultFindingKind kind)
    {
        var totals = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (var f in findings)
        {
            if (f.Kind != kind)
            {
                continue;
            }
            totals[f.Type] = totals.TryGetValue(f.Type, out var n) ? n + f.Count : f.Count;
        }
        return totals;
    }

    private static int Sum(IReadOnlyDictionary<string, int> counts) => counts.Values.Sum();

    /// <summary>Build the receipt block for a completed scan. Property declaration
    /// order on ToolResultScanReceiptBlock IS the emitted key order.</summary>
    public static ToolResultScanReceiptBlock Build(string toolName, string? serverUri, ToolResultScanResult result, string sdkVersion)
    {
        var pii = CountsByType(result.Findings, ToolResultFindingKind.Pii);
        var injection = CountsByType(result.Findings, ToolResultFindingKind.Injection);

        return new ToolResultScanReceiptBlock
        {
            Blocked = result.Blocked,
            Findings = new ToolResultScanFindingCounts { Injection = injection, Pii = pii },
            InjectionRuleset = InjectionHeuristics.Ruleset,
            Reason = result.Reason,
            SdkVersion = sdkVersion,
            ServerUri = serverUri,
            ToolName = toolName,
            Totals = new ToolResultScanTotals { Injection = Sum(injection), Pii = Sum(pii) },
        };
    }
}

public static class ToolResultScanQueries
{
    /// <summary>Distinct PII types in a scan result, for the attestation canonical form.</summary>
    public static IReadOnlyList<string> PiiTypes(IReadOnlyList<ToolResultFinding> findings) =>
        findings
            .Where(f => f.Kind == ToolResultFindingKind.Pii)
            .Select(f => f.Type)
            .Distinct()
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

    /// <summary>Total PII match count in a scan result.</summary>
    public static int PiiCount(IReadOnlyList<ToolResultFinding> findings) =>
        findings.Where(f => f.Kind == ToolResultFindingKind.Pii).Sum(f => f.Count);

    /// <summary>Total injection match count in a scan result.</summary>
    public static int InjectionCount(IReadOnlyList<ToolResultFinding> findings) =>
        findings.Where(f => f.Kind == ToolResultFindingKind.Injection).Sum(f => f.Count);
}
