using System.Text.RegularExpressions;

namespace TorkGovernance.Core;

/// <summary>
/// Prompt-injection heuristics for tool-result scanning (DECIDED-TACT2-V2-C).
///
/// Ported from tork-js-sdk/src/tool-result-scan.ts. The .NET SDK had NO
/// injection heuristics before this module, so these are new here -- but
/// every injection finding is labelled <c>heuristic:&lt;type&gt;</c> (see
/// <see cref="HeuristicPrefix"/>) so no caller can mistake a regex hit for a
/// verified determination.
///
/// Conservative on purpose. Each pattern targets a phrase that has no
/// plausible reason to appear in a legitimate tool result -- a database row,
/// a search hit, a file listing. Broader "suspicious language" matching
/// would fire on ordinary documentation and support tickets, and an alert
/// nobody believes is worse than no alert.
///
/// ENGINE NOTES: .NET's System.Text.RegularExpressions, like JS's engine, is
/// a backtracking NFA -- unlike Go's RE2, nothing here needed a lookaround
/// substitution or other workaround. The only translation was syntactic:
/// JS's /pattern/gi and /pattern/gim flags became RegexOptions.IgnoreCase
/// and RegexOptions.IgnoreCase | RegexOptions.Multiline (JS's mandatory /g
/// needed no equivalent flag -- Regex.Matches already finds every match),
/// and literal forward slashes that JS had to escape only because its regex
/// literals are slash-delimited (<c>https:\/\/</c>) are left unescaped here
/// (<c>https://</c>), since .NET regex strings are not slash-delimited and
/// \/ has no special meaning in either engine -- purely cosmetic, not a
/// content change.
/// </summary>
public static class InjectionHeuristics
{
    /// <summary>
    /// Prefix on every injection finding's type. Not cosmetic: these
    /// patterns are regexes over untrusted text, they carry false positives
    /// and false negatives, and the label travels with the finding into the
    /// receipt.
    /// </summary>
    public const string HeuristicPrefix = "heuristic:";

    /// <summary>
    /// Identifies this exact pattern set in receipts. Bump when the patterns
    /// change, so a receipt says which ruleset produced its counts. Every
    /// SDK mirroring this implementation must emit the SAME value for the
    /// same ruleset -- it is a shared identifier, not a per-language one.
    /// </summary>
    public const string Ruleset = "tork-injection-heuristics-v1";

    public sealed record InjectionPatternDefinition(string Type, Regex Pattern);

    private const RegexOptions Gi = RegexOptions.IgnoreCase | RegexOptions.Compiled;
    private const RegexOptions Gim = RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled;

    public static readonly IReadOnlyList<InjectionPatternDefinition> Patterns = new[]
    {
        // -- instruction override --------------------------------------------
        new InjectionPatternDefinition(
            "instruction_override",
            new Regex(
                @"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b",
                Gi)),
        new InjectionPatternDefinition(
            "instruction_override",
            new Regex(
                @"\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b",
                Gi)),
        new InjectionPatternDefinition(
            "instruction_override",
            new Regex(@"\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b", Gi)),

        // -- role reassignment ------------------------------------------------
        new InjectionPatternDefinition(
            "role_reassignment",
            new Regex(@"\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b", Gi)),
        new InjectionPatternDefinition(
            "role_reassignment",
            new Regex(
                @"\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b",
                Gi)),
        new InjectionPatternDefinition(
            "role_reassignment",
            new Regex(@"\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:", Gi)),
        new InjectionPatternDefinition(
            "role_reassignment",
            new Regex(@"\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b", Gi)),
        new InjectionPatternDefinition(
            "role_reassignment",
            new Regex(
                @"\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b",
                Gi)),
        new InjectionPatternDefinition(
            // A role header smuggled into content -- "system:" / "<|im_start|>system"
            // at the start of a line is a conversation-structure forgery, not prose.
            "role_reassignment",
            new Regex(@"^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)", Gim)),

        // -- exfiltration -----------------------------------------------------
        new InjectionPatternDefinition(
            // A markdown image/link whose URL carries the content out as a
            // query parameter -- the classic zero-click exfiltration shape.
            "exfiltration_url",
            new Regex(
                @"!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)",
                Gi)),
        new InjectionPatternDefinition(
            "exfiltration_url",
            new Regex(
                @"\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=",
                Gi)),
        new InjectionPatternDefinition(
            "exfiltration_url",
            new Regex(@"\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+", Gi)),
    };

    /// <summary>Distinct injection types the ruleset can emit: exfiltration_url,
    /// instruction_override, role_reassignment.</summary>
    public static readonly IReadOnlyList<string> Types = Patterns
        .Select(p => p.Type)
        .Distinct()
        .OrderBy(t => t, StringComparer.Ordinal)
        .ToList();
}
