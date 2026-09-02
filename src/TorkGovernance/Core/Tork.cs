using System.Text.RegularExpressions;

namespace TorkGovernance.Core;

/// <summary>
/// Tork Governance SDK for .NET.
/// Provides PII detection, redaction, and compliance receipts for AI applications.
/// </summary>
public class Tork
{
    private readonly TorkConfig _config;
    private readonly Dictionary<string, Regex> _patterns;

    public Tork(TorkConfig? config = null)
    {
        _config = config ?? new TorkConfig();
        _patterns = GetDefaultPatterns();

        if (_config.CustomPatterns != null)
        {
            foreach (var pattern in _config.CustomPatterns)
            {
                _patterns[pattern.Key] = new Regex(pattern.Value, RegexOptions.Compiled);
            }
        }
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
        var piiDetected = DetectPII(content);
        var action = DetermineAction(piiDetected);
        // Security fix (Leak 1): always redact output when PII is present,
        // regardless of action (DENY and ESCALATE must not expose raw input).
        var output = piiDetected.Count > 0 ? Redact(content, piiDetected) : content;

        // Security fix (Leak 2): never store raw matched values in the result;
        // replace each match value with "[REDACTED]" while preserving type counts.
        var piiSanitized = piiDetected.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.Select(_ => "[REDACTED]").ToList()
        );

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

    private Dictionary<string, List<string>> DetectPII(string content)
    {
        var detected = new Dictionary<string, List<string>>();

        foreach (var (type, pattern) in _patterns)
        {
            var matches = pattern.Matches(content);
            if (matches.Count > 0)
            {
                detected[type] = matches.Select(m => m.Value).ToList();
            }
        }

        return detected;
    }

    private string DetermineAction(Dictionary<string, List<string>> piiDetected)
    {
        return piiDetected.Count == 0 ? "allow" : _config.DefaultAction;
    }

    private string Redact(string content, Dictionary<string, List<string>> piiDetected)
    {
        var redacted = content;

        foreach (var (type, matches) in piiDetected)
        {
            foreach (var match in matches)
            {
                redacted = redacted.Replace(match, $"[{type}_REDACTED]");
            }
        }

        return redacted;
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

    private static Dictionary<string, Regex> GetDefaultPatterns()
    {
        return new Dictionary<string, Regex>
        {
            ["SSN"] = new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled),
            ["EMAIL"] = new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", RegexOptions.Compiled),
            ["PHONE"] = new Regex(@"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", RegexOptions.Compiled),
            ["CREDIT_CARD"] = new Regex(@"\b(?:\d{4}[-\s]?){3}\d{4}\b", RegexOptions.Compiled),
            ["IP_ADDRESS"] = new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)
        };
    }
}
