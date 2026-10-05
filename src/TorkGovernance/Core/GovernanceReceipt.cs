using System.Text.Json.Serialization;

namespace TorkGovernance.Core;

/// <summary>
/// Cryptographic receipt for governance evaluations.
/// </summary>
public class GovernanceReceipt
{
    public required string ReceiptId { get; set; }
    public required DateTime Timestamp { get; set; }
    public required string Action { get; set; }
    public required List<string> PiiTypesDetected { get; set; }
    public required string PolicyVersion { get; set; }

    /// <summary>
    /// Agent telemetry (agent_id, agent_role, session_id, session_turn) echoed
    /// from <see cref="GovernOptions.SessionContext"/>. Omitted from the
    /// serialized receipt when the caller supplied none.
    /// </summary>
    [JsonPropertyName("session_context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SessionContext? SessionContext { get; set; }

    /// <summary>Set only on receipts produced by Tork.ScanToolResult.</summary>
    [JsonPropertyName("tool_result_scan")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ToolResultScanReceiptBlock? ToolResultScan { get; set; }
}
