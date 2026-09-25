using System.Text.RegularExpressions;

namespace TorkGovernance.Core;

/// <summary>
/// Tork Governance SDK for .NET.
/// Provides PII detection, redaction, and compliance receipts for AI applications.
/// </summary>
public class Tork
{
    private readonly TorkConfig _config;

    public Tork(TorkConfig? config = null)
    {
        _config = config ?? new TorkConfig();
        // TorkConfig.CustomPatterns is passed straight to Pii.DetectPii on every
        // call. It used to be merged into a second, private pattern table here,
        // which is what let Govern and ScanToolResult drift apart.
    }

    /// <summary>
    /// Govern content for PII and policy violations.
    /// </summary>
    public GovernanceResult Govern(string content)
    {
        return Govern(content, null);
    }

    /// <summary>
    /// Govern content with regional and industry-specific PII detection.
    /// </summary>
    public GovernanceResult Govern(string content, GovernOptions? options)
    {
        // ONE DETECTOR. Until 0.3.0 this method ran its own pattern table and
        // redacted by literal String.Replace of each matched VALUE -- which
        // replaced every other occurrence of the same text anywhere in the
        // content, used the dictionary key as the label (`[ssn_REDACTED]`
        // rather than the JS-identical `[SSN_REDACTED]`), and knew nothing
        // about the country registry. It now goes through Pii.DetectPii, the
        // same detector ScanToolResult uses, so the two paths cannot drift.
        var detection = Pii.DetectPii(content, _config.CustomPatterns, options?.Region);

        // Security fix (Leak 2): never store raw matched values in the result;
        // each value is "[REDACTED]" while the per-type counts are preserved.
        var piiSanitized = new Dictionary<string, List<string>>();
        foreach (var m in detection.Matches)
        {
            if (!piiSanitized.TryGetValue(m.Type, out var list))
            {
                list = new List<string>();
                piiSanitized[m.Type] = list;
            }
            list.Add("[REDACTED]");
        }
        foreach (var m in detection.CountryMatches)
        {
            if (!piiSanitized.TryGetValue(m.Name, out var list))
            {
                list = new List<string>();
                piiSanitized[m.Name] = list;
            }
            list.Add("[REDACTED]");
        }

        var piiDetected = piiSanitized;
        var action = DetermineAction(piiDetected);
        // Security fix (Leak 1): always redact output when PII is present,
        // regardless of action (DENY and ESCALATE must not expose raw input).
        var output = detection.HasPii ? detection.RedactedText : content;

        var receipt = new GovernanceReceipt
        {
            ReceiptId = GenerateReceiptId(),
            Timestamp = DateTime.UtcNow,
            Action = action,
            PiiTypesDetected = piiDetected.Keys.ToList(),
            PolicyVersion = _config.PolicyVersion
        };

        return new GovernanceResult
        {
            Action = action,
            Output = output,
            Pii = piiSanitized,
            Receipt = receipt,
            Region = options?.Region,
            Industry = options?.Industry,
            SessionContext = options?.SessionContext
        };
    }

    private string DetermineAction(Dictionary<string, List<string>> piiDetected)
    {
        return piiDetected.Count == 0 ? "allow" : _config.DefaultAction;
    }

    /// <summary>
    /// Scan a tool result for PII and prompt injection before it is
    /// appended to model context, and record the scan as a governance
    /// receipt carrying a tool_result_scan block (attested_by="client",
    /// capture_mode="edge"). Pure and synchronous: makes no network call.
    ///
    /// The receipt's Action follows the four-way mapping shared with the JS
    /// and Go SDKs: blocked -> "deny"; an injection finding present ->
    /// "escalate"; otherwise a PII finding present -> "redact"; otherwise ->
    /// "allow". Injection takes priority over PII when a scan contains
    /// both, matching a payload that is both leaking data and carrying an
    /// attempted takeover.
    /// </summary>
    public ToolResultScanReport ScanToolResult(ToolResultScanInput input, ToolResultScanOptions? options = null)
    {
        var scan = Core.ToolResultScan.Scan(input, options);
        var action = DetermineToolResultScanAction(scan);
        var block = ToolResultScanReceiptBuilder.Build(input.ToolName, input.ServerUri, scan, SdkVersion.Value);

        var receipt = new GovernanceReceipt
        {
            ReceiptId = GenerateReceiptId(),
            Timestamp = DateTime.UtcNow,
            Action = action,
            PiiTypesDetected = ToolResultScanQueries.PiiTypes(scan.Findings).ToList(),
            PolicyVersion = _config.PolicyVersion,
            ToolResultScan = block,
        };

        return new ToolResultScanReport
        {
            Sanitized = scan.Sanitized,
            Findings = scan.Findings,
            Blocked = scan.Blocked,
            Reason = scan.Reason,
            Receipt = receipt,
        };
    }

    private static string DetermineToolResultScanAction(ToolResultScanResult scan)
    {
        if (scan.Blocked)
        {
            return "deny";
        }

        var hasInjection = scan.Findings.Any(f => f.Kind == ToolResultFindingKind.Injection);
        if (hasInjection)
        {
            return "escalate";
        }

        var hasPii = scan.Findings.Any(f => f.Kind == ToolResultFindingKind.Pii);
        return hasPii ? "redact" : "allow";
    }

    private static string GenerateReceiptId()
    {
        return $"tork_{Guid.NewGuid():N}";
    }

}
