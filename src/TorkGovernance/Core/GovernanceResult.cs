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
    public string[]? Region { get; set; }
    public string? Industry { get; set; }
}

/// <summary>
/// Options for regional and industry-specific PII detection.
/// </summary>
public class GovernOptions
{
    public string[]? Region { get; set; }
    public string? Industry { get; set; }
}
