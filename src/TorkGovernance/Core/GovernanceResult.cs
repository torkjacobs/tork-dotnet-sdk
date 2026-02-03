namespace TorkGovernance.Core;

/// <summary>
/// Result of a governance evaluation.
/// </summary>
public class GovernanceResult
{
    public required string Action { get; set; }
    public required string Output { get; set; }
    public required Dictionary<string, List<string>> Pii { get; set; }
    public required GovernanceReceipt Receipt { get; set; }
}
