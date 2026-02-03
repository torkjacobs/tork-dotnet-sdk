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
}
