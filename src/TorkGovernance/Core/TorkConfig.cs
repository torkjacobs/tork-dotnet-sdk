namespace TorkGovernance.Core;

/// <summary>
/// Configuration for Tork Governance.
/// </summary>
public class TorkConfig
{
    public string DefaultAction { get; set; } = "redact";
    public string PolicyVersion { get; set; } = "1.0.0";
    public Dictionary<string, string>? CustomPatterns { get; set; }
}
