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
    /// <summary>Agent/session context when provided.</summary>
    public SessionContext? SessionContext { get; set; }
}

/// <summary>
/// Agent/session context for multi-agent governance tracking.
/// All fields are optional. When provided, they are included in the POST body
/// to /api/v1/govern and returned in the receipt under session_context.
/// </summary>
public class SessionContext
{
    /// <summary>Identifier for the agent making the call.</summary>
    public string? AgentId { get; set; }
    /// <summary>Role of the agent: "planner", "worker", or "judge".</summary>
    public string? AgentRole { get; set; }
    /// <summary>Groups all calls from the same agent session.</summary>
    public string? SessionId { get; set; }
    /// <summary>Position in the conversation (1, 2, 3...).</summary>
    public int? SessionTurn { get; set; }
}

/// <summary>
/// Options for regional and industry-specific PII detection.
/// </summary>
public class GovernOptions
{
    public string[]? Region { get; set; }
    public string? Industry { get; set; }
    /// <summary>Optional agent/session context for multi-agent tracking.</summary>
    public SessionContext? SessionContext { get; set; }
}
