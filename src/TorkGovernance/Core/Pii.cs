using System.Text.RegularExpressions;

using TorkGovernance.CountryPii;

namespace TorkGovernance.Core;

/// <summary>
/// The on-device PII detector for tool-result scanning (DECIDED-TACT2-V2-C).
///
/// Ported from tork-js-sdk/src/pii.ts. PARITY TIER 1: the same 10-type basic
/// PII vocabulary as the JS SDK (ssn, credit_card, email, phone, address,
/// ip_address, date_of_birth, passport, drivers_license, bank_account), with
/// JS-identical type labels and redaction markers. This SDK does not carry
/// the Python SDK's regional/industry pattern tier (AU/US/GB/EU/AE/...
/// profiles) -- that is a separate, larger effort and out of scope here.
///
/// Deliberately a SINGLE table (<see cref="Patterns"/>) that is both the
/// declaration of which PII types this SDK detects AND the source of their
/// patterns, so a type cannot be declared without a live pattern by
/// construction. This directly avoids the bug class every other SDK port
/// hit: JS, Go and Python each had at least one PII type declared (in an
/// enum or type union) with no corresponding pattern in the pattern table --
/// e.g. the Go SDK's PIIType const block once listed 10 values while
/// defaultPatterns implemented only 7, silently letting passport,
/// drivers_license and bank_account matches through unmasked and unflagged.
/// See ToolResultScanParityTests for the guard that keeps this table
/// honest going forward.
///
/// Pure and local: no I/O, no network, no clock.
/// </summary>
public static class Pii
{
    /// <summary>One PII type's detection pattern and redaction marker.</summary>
    public sealed record PiiPatternDefinition(string Type, Regex Pattern, string Redaction);

    /// <summary>
    /// Ordered exactly as tork-js-sdk/src/pii.ts declares PII_PATTERNS.
    /// Order matters: redaction is applied pattern-by-pattern over the
    /// already-partially-redacted text (see <see cref="DetectPii"/>), and
    /// bank_account's broad 8-17-digit catch-all pattern is deliberately
    /// LAST so it never consumes digits that belong to an earlier, more
    /// specific type (ssn, credit_card, date_of_birth, ...).
    ///
    /// Regex sources are ported verbatim from the JS RegExp literals; only
    /// the flags -> RegexOptions translation changed (JS /gi -> IgnoreCase,
    /// JS's mandatory /g is simply how System.Text.RegularExpressions.Regex
    /// already behaves via Matches/Replace, so it needed no explicit flag).
    /// No pattern here uses a JS regex feature .NET's regex engine lacks.
    /// </summary>
    public static readonly IReadOnlyList<PiiPatternDefinition> Patterns = new[]
    {
        new PiiPatternDefinition(
            "ssn",
            new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled),
            "[SSN_REDACTED]"),
        new PiiPatternDefinition(
            "credit_card",
            new Regex(@"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", RegexOptions.Compiled),
            "[CARD_REDACTED]"),
        new PiiPatternDefinition(
            "email",
            new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled),
            "[EMAIL_REDACTED]"),
        new PiiPatternDefinition(
            "phone",
            new Regex(@"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", RegexOptions.Compiled),
            "[PHONE_REDACTED]"),
        new PiiPatternDefinition(
            "address",
            new Regex(
                @"\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
                RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "[ADDRESS_REDACTED]"),
        new PiiPatternDefinition(
            "ip_address",
            new Regex(
                @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                RegexOptions.Compiled),
            "[IP_REDACTED]"),
        new PiiPatternDefinition(
            "date_of_birth",
            new Regex(@"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b", RegexOptions.Compiled),
            "[DOB_REDACTED]"),
        new PiiPatternDefinition(
            "passport",
            new Regex(@"\b[A-Z]{1,2}\d{6,9}\b", RegexOptions.Compiled),
            "[PASSPORT_REDACTED]"),
        new PiiPatternDefinition(
            "drivers_license",
            new Regex(@"\b[A-Z]\d{7,14}\b", RegexOptions.Compiled),
            "[DL_REDACTED]"),
        new PiiPatternDefinition(
            "bank_account",
            new Regex(@"\b\d{8,17}\b", RegexOptions.Compiled),
            "[ACCOUNT_REDACTED]"),
    };

    /// <summary>One matched span. Value is always the literal "[REDACTED]"
    /// marker, never the matched text -- matches never leave this module.</summary>
    public sealed class PiiMatch
    {
        public required string Type { get; init; }
        public required string Value { get; init; }
        public required int StartIndex { get; init; }
        public required int EndIndex { get; init; }
    }

    public sealed class PiiDetectionResult
    {
        public required bool HasPii { get; init; }
        public required IReadOnlyList<string> Types { get; init; }
        public required int Count { get; init; }
        public required IReadOnlyList<PiiMatch> Matches { get; init; }
        public required string RedactedText { get; init; }

        /// <summary>
        /// Country-registry detections. Kept separate from <see cref="Matches"/>
        /// so the ten L0 type labels stay the closed set they have always been.
        /// </summary>
        public IReadOnlyList<PiiCountry.CountryPiiMatch> CountryMatches { get; init; } =
            Array.Empty<PiiCountry.CountryPiiMatch>();

        /// <summary>Redaction labels of those matches, e.g. "NATIONAL_ID".</summary>
        public IReadOnlyList<string> CountryLabels { get; init; } = Array.Empty<string>();

        /// <summary>Country profiles the text activated, in registry order.</summary>
        public IReadOnlyList<string> Regions { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// Detect PII in text and return detection results with redacted text.
    ///
    /// ENGINE DIFFERENCE from the JS source: JS applies each custom pattern
    /// via <c>String.prototype.replace(pattern, ...)</c>, which redacts only
    /// the FIRST match unless the caller's RegExp carries a 'g' flag --
    /// global-ness is a property of the RegExp object the caller constructed.
    /// .NET's <see cref="Regex"/> has no equivalent per-instance "global"
    /// flag: <c>Regex.Replace</c> always replaces every match. customPatterns
    /// here are therefore always applied as if global. This only changes
    /// behavior for a caller-supplied pattern that matches more than once in
    /// one string, and (as in the JS source) custom-pattern redactions are
    /// never counted as findings either way.
    /// </summary>
    public static PiiDetectionResult DetectPii(
        string text,
        IReadOnlyDictionary<string, string>? customPatterns = null,
        IReadOnlyList<string>? regionOverride = null)
    {
        var matches = new List<PiiMatch>();
        var detectedTypes = new List<string>();

        // L0: collect every match against the ORIGINAL text.
        //
        // REDACTION IS ONE PASS. Until 0.2.0 each type was redacted with its own
        // Regex.Replace over text a previous type had already rewritten, while
        // Matches carried indices into the ORIGINAL text. Two types matching
        // overlapping spans could leave half an identifier standing beside a
        // redaction token -- digits exposed in output the caller had been told
        // was redacted. Every match is now collected against the original text,
        // overlaps are resolved before anything is rewritten, and the surviving
        // spans are spliced right to left in a single pass.
        var l0 = new List<(PiiMatch Match, string Redaction)>();
        foreach (var def in Patterns)
        {
            foreach (Match m in def.Pattern.Matches(text))
            {
                if (m.Length == 0) continue;
                l0.Add((new PiiMatch
                {
                    Type = def.Type,
                    Value = "[REDACTED]",
                    StartIndex = m.Index,
                    EndIndex = m.Index + m.Length,
                }, def.Redaction));
            }
        }

        // Country layer. An explicit region from the caller is authoritative;
        // otherwise the profiles are activated from the content itself.
        var regions = regionOverride is { Count: > 0 }
            ? regionOverride.Select(r => r.ToUpperInvariant()).ToList()
            : PiiCountry.InferRegions(text).ToList();
        var countryMatches = PiiCountry.Detect(text, PiiCountry.PatternsForRegions(regions));

        // Resolve overlaps before anything is rewritten. A country identifier
        // supersedes any L0 span it fully contains -- the cloud does the same,
        // which is how a Saudi national ID stops coming back as
        // [PHONE_REDACTED].
        var claimed = new List<(int Start, int End)>();
        var spans = new List<PiiCountry.RedactionSpan>();
        foreach (var c in countryMatches)
        {
            claimed.Add((c.StartIndex, c.EndIndex));
            spans.Add(new PiiCountry.RedactionSpan
            {
                StartIndex = c.StartIndex,
                EndIndex = c.EndIndex,
                Redaction = c.Redaction,
            });
        }

        foreach (var (m, redaction) in l0)
        {
            var s = m.StartIndex;
            var e = m.EndIndex;
            var overlapping = claimed.Where(c => s < c.End && e > c.Start).ToList();
            if (overlapping.Count > 0)
            {
                var swallowsAll = overlapping.All(c =>
                {
                    var (cs, ce) = PiiCountry.TrimmedCore(text, c.Start, c.End);
                    return s <= cs && e >= ce;
                });
                if (!swallowsAll) continue;

                // An L0 span that fully contains a country span still loses:
                // the country label is the more specific claim.
                var hitsCountry = overlapping.Any(o =>
                    countryMatches.Any(c => c.StartIndex == o.Start && c.EndIndex == o.End));
                if (hitsCountry) continue;

                foreach (var o in overlapping)
                {
                    claimed.Remove(o);
                    spans.RemoveAll(sp => sp.StartIndex == o.Start && sp.EndIndex == o.End);
                }
            }

            claimed.Add((s, e));
            spans.Add(new PiiCountry.RedactionSpan
            {
                StartIndex = s,
                EndIndex = e,
                Redaction = redaction,
            });
            matches.Add(m);
            if (!detectedTypes.Contains(m.Type)) detectedTypes.Add(m.Type);
        }

        var redactedText = PiiCountry.ApplyRedactions(text, spans);

        if (customPatterns is { Count: > 0 })
        {
            // Applied in sorted-name order for determinism: .NET Dictionary
            // enumeration order is not a contractual guarantee the way JS
            // Object.entries insertion order is. Redact-only, uncounted --
            // order only matters when two custom patterns overlap the same
            // span, an edge case (same documented tradeoff the Go port made).
            foreach (var name in customPatterns.Keys.OrderBy(k => k, StringComparer.Ordinal))
            {
                var pattern = new Regex(customPatterns[name], RegexOptions.Compiled);
                redactedText = pattern.Replace(redactedText, $"[{name.ToUpperInvariant()}_REDACTED]");
            }
        }

        var countryLabels = new List<string>();
        foreach (var c in countryMatches)
        {
            if (!countryLabels.Contains(c.Label)) countryLabels.Add(c.Label);
        }

        return new PiiDetectionResult
        {
            HasPii = matches.Count + countryMatches.Count > 0,
            Types = detectedTypes,
            Count = matches.Count + countryMatches.Count,
            Matches = matches.OrderBy(m => m.StartIndex).ToList(),
            RedactedText = redactedText,
            CountryMatches = countryMatches,
            CountryLabels = countryLabels,
            Regions = regions,
        };
    }
}
