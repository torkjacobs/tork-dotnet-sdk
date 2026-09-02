using System.Text.Json;
using System.Text.RegularExpressions;

namespace TorkGovernance.Core;

/// <summary>
/// Tool-result scanning (DECIDED-TACT2-V2-C), ported from
/// tork-js-sdk/src/tool-result-scan.ts (see also tork-go-sdk/toolresultscan.go
/// for a second statically-typed reference).
///
/// A tool result returned by an MCP server -- or by any external system the
/// caller does not control -- is untrusted input that is about to be
/// appended to a model's context. ScanToolResult scans it BEFORE that
/// happens, on-device, for two things:
///
///   1. PII, using the SAME on-device detector as Tork.ScanToolResult uses
///      for its receipt (<see cref="Pii.DetectPii"/>). No second scanner.
///   2. Prompt injection, using the conservative heuristic pattern set in
///      <see cref="InjectionHeuristics"/>.
///
/// ZERO NETWORK. Every member here is pure and synchronous: no HttpClient,
/// no I/O, no clock read. The payload never leaves the machine.
///
/// WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
/// the caller attests to. It is not gateway-side enforcement -- a
/// compromised or simply careless caller can skip it entirely, and Tork
/// cannot tell. Enforcement at the gateway, where skipping is not an
/// option, is a separate and later control.
///
/// TRAVERSAL SHAPE (language-specific choice): JS walks plain objects/arrays
/// natively; Go walks map[string]interface{}/[]interface{} via reflection.
/// .NET has several competing "any JSON value" representations
/// (Dictionary&lt;string,object?&gt;, System.Text.Json.Nodes.JsonNode,
/// JsonElement, ...); this port walks the plain-CLR-object shape --
/// <see cref="IDictionary{TKey,TValue}"/> of &lt;string, object?&gt; for
/// objects (e.g. Dictionary&lt;string, object?&gt;) and
/// <see cref="IList{T}"/> of object? for arrays (e.g. List&lt;object?&gt;,
/// object?[]) -- the direct .NET analogue of JS's plain objects/arrays and
/// Go's map/slice. JsonNode/JsonElement payloads are not walked directly;
/// deserialize into the plain-object shape first (e.g.
/// <c>JsonSerializer.Deserialize&lt;Dictionary&lt;string, object?&gt;&gt;</c>)
/// if scanning a JSON document.
/// </summary>
public enum ToolResultFindingKind
{
    Pii,
    Injection,
}

/// <summary>One (kind, type, location) match tally.</summary>
public sealed class ToolResultFinding
{
    /// <summary>Pii for a detector match, Injection for a heuristic pattern match.</summary>
    public required ToolResultFindingKind Kind { get; init; }

    /// <summary>
    /// For kind Pii, a PII type string ("ssn", "email", ...). For kind
    /// Injection, always <c>heuristic:&lt;name&gt;</c> -- the prefix is part
    /// of the value, not decoration, so a downstream reader of a receipt
    /// cannot mistake a pattern hit for a verified determination.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>Number of matches of this (kind, type) at this location.</summary>
    public required int Count { get; init; }

    /// <summary>JSON path of the string the matches were found in, e.g. "$.content[0].text".</summary>
    public required string Location { get; init; }
}

public sealed class ToolResultScanInput
{
    /// <summary>Name of the tool that produced this result. Recorded on the receipt.</summary>
    public required string ToolName { get; init; }

    /// <summary>URI of the MCP server (or other origin). Recorded on the receipt when present.</summary>
    public string? ServerUri { get; init; }

    /// <summary>
    /// The tool result itself. Supported shapes: string leaves,
    /// IDictionary&lt;string, object?&gt; objects, IList&lt;object?&gt;
    /// arrays (including plain object?[] arrays), and any other CLR value
    /// (numbers, bools, null, ...) which passes through unscanned -- see
    /// the traversal note on this file. Never leaves the machine.
    /// </summary>
    public object? Payload { get; init; }
}

public sealed class ToolResultScanOptions
{
    /// <summary>
    /// Block the result when the injection heuristics fire. Default false:
    /// detect and report, let the caller decide. When true and an injection
    /// pattern matches, Blocked is true, Reason is set, and Sanitized is
    /// null -- there is deliberately no masked payload to accidentally
    /// append.
    /// </summary>
    public bool BlockOnInjection { get; init; }

    /// <summary>
    /// Extra redaction patterns, same shape and semantics as this SDK's
    /// TorkConfig.CustomPatterns (pattern strings, not precompiled Regex
    /// objects -- kept consistent with that existing config surface rather
    /// than mirroring JS's Record&lt;string, RegExp&gt; literally). NOTE
    /// (inherited from Pii.DetectPii): custom patterns redact but are not
    /// counted, so they can change Sanitized without producing a finding.
    /// </summary>
    public IReadOnlyDictionary<string, string>? CustomPatterns { get; init; }

    /// <summary>
    /// Maximum nesting depth to walk. Deeper values are passed through
    /// unscanned and unmodified. Null means "use the default" (32); pass 0
    /// explicitly to scan nothing but the root value itself.
    /// </summary>
    public int? MaxDepth { get; init; }
}

public sealed class ToolResultScanResult
{
    /// <summary>
    /// The payload with PII masked in place, structurally identical
    /// otherwise. Null when Blocked is true. Sub-trees containing no PII
    /// keep their original object reference, so a clean payload's
    /// containers come back as the exact same objects that were passed in.
    /// </summary>
    public object? Sanitized { get; init; }

    public required IReadOnlyList<ToolResultFinding> Findings { get; init; }
    public required bool Blocked { get; init; }

    /// <summary>Present only when Blocked is true.</summary>
    public string? Reason { get; init; }
}

public static class ToolResultScan
{
    private const int DefaultMaxDepth = 32;

    private static readonly Regex LocationIdentifier = new(@"^[A-Za-z_$][A-Za-z0-9_$]*$", RegexOptions.Compiled);

    private static string ChildPath(string parent, string key)
        => LocationIdentifier.IsMatch(key) ? $"{parent}.{key}" : $"{parent}[{JsonSerializer.Serialize(key)}]";

    /// <summary>
    /// Scan one string: PII (via the shared detector) then injection
    /// heuristics. Returns the masked string; findings are appended in
    /// place, keyed to location.
    /// </summary>
    private static string ScanString(
        string text,
        string location,
        IReadOnlyDictionary<string, string>? customPatterns,
        List<ToolResultFinding> findings)
    {
        var pii = Pii.DetectPii(text, customPatterns);

        if (pii.Count > 0)
        {
            // Counts per type, emitted in a stable (sorted) order so two
            // runs over the same payload produce identical findings.
            var perType = new SortedDictionary<string, int>(StringComparer.Ordinal);
            foreach (var match in pii.Matches)
            {
                perType[match.Type] = perType.TryGetValue(match.Type, out var n) ? n + 1 : 1;
            }
            foreach (var (type, count) in perType)
            {
                findings.Add(new ToolResultFinding
                {
                    Kind = ToolResultFindingKind.Pii,
                    Type = type,
                    Count = count,
                    Location = location,
                });
            }
        }

        var perInjection = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (var def in InjectionHeuristics.Patterns)
        {
            var count = def.Pattern.Matches(text).Count;
            if (count > 0)
            {
                perInjection[def.Type] = perInjection.TryGetValue(def.Type, out var n) ? n + count : count;
            }
        }
        foreach (var (type, count) in perInjection)
        {
            findings.Add(new ToolResultFinding
            {
                Kind = ToolResultFindingKind.Injection,
                Type = InjectionHeuristics.HeuristicPrefix + type,
                Count = count,
                Location = location,
            });
        }

        return pii.RedactedText;
    }

    /// <summary>
    /// Walk the payload, scanning every string. Returns a structure with
    /// PII masked in place; sub-trees with nothing to mask keep their
    /// original reference (so an untouched payload's containers are
    /// reference-equal to the input). Only strings are scanned -- a bank
    /// account stored as a JSON number is NOT detected. Cycles are left
    /// as-is and not re-entered.
    /// </summary>
    private static object? Walk(
        object? value,
        string location,
        int depth,
        int maxDepth,
        IReadOnlyDictionary<string, string>? customPatterns,
        List<ToolResultFinding> findings,
        HashSet<object> seen)
    {
        if (value is string s)
        {
            return ScanString(s, location, customPatterns, findings);
        }

        if (value is null || depth >= maxDepth)
        {
            return value;
        }

        if (value is IDictionary<string, object?> dict)
        {
            if (!seen.Add(value))
            {
                return value;
            }

            var changed = false;
            var outDict = new Dictionary<string, object?>(dict.Count);
            foreach (var (key, item) in dict)
            {
                var next = Walk(item, ChildPath(location, key), depth + 1, maxDepth, customPatterns, findings, seen);
                if (!ReferenceEquals(next, item))
                {
                    changed = true;
                }
                outDict[key] = next;
            }
            return changed ? outDict : value;
        }

        if (value is IList<object?> list)
        {
            if (!seen.Add(value))
            {
                return value;
            }

            var changed = false;
            var outList = new List<object?>(list.Count);
            for (var i = 0; i < list.Count; i++)
            {
                var item = list[i];
                var next = Walk(item, $"{location}[{i}]", depth + 1, maxDepth, customPatterns, findings, seen);
                if (!ReferenceEquals(next, item))
                {
                    changed = true;
                }
                outList.Add(next);
            }
            return changed ? outList : value;
        }

        return value;
    }

    /// <summary>
    /// Scan a tool result for PII and prompt injection before it is
    /// appended to model context. Pure, synchronous, on-device: makes no
    /// network call and mutates nothing reachable from input.Payload.
    ///
    /// For the receipt-linked form (attested_by="client", capture_mode="edge"),
    /// use Tork.ScanToolResult, which wraps this and records the scan.
    /// </summary>
    public static ToolResultScanResult Scan(ToolResultScanInput input, ToolResultScanOptions? options = null)
    {
        options ??= new ToolResultScanOptions();
        var findings = new List<ToolResultFinding>();
        var maxDepth = options.MaxDepth ?? DefaultMaxDepth;

        var sanitized = Walk(
            input.Payload,
            "$",
            0,
            maxDepth,
            options.CustomPatterns,
            findings,
            new HashSet<object>(ReferenceEqualityComparer.Instance));

        var injectionCount = findings.Where(f => f.Kind == ToolResultFindingKind.Injection).Sum(f => f.Count);
        var blocked = options.BlockOnInjection && injectionCount > 0;

        if (blocked)
        {
            var types = findings
                .Where(f => f.Kind == ToolResultFindingKind.Injection)
                .Select(f => f.Type)
                .Distinct()
                .OrderBy(t => t, StringComparer.Ordinal);

            var reason =
                $"Blocked: {injectionCount} prompt-injection heuristic match(es) [{string.Join(", ", types)}] in the result of " +
                $"tool \"{input.ToolName}\". These are heuristic pattern matches ({InjectionHeuristics.Ruleset}), not a verified " +
                "determination. sanitized is null so no masked copy can be appended to context by accident.";

            return new ToolResultScanResult
            {
                Sanitized = null,
                Findings = findings,
                Blocked = true,
                Reason = reason,
            };
        }

        return new ToolResultScanResult { Sanitized = sanitized, Findings = findings, Blocked = false };
    }
}
