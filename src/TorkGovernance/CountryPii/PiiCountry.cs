// The country layer: 24 country profiles, 51 patterns, 20 check digits.
//
// This implements the seven rules that generated/sdk-registry/README.md marks
// SDK, from the bundle alone. Bundle 1.1.0 carries the data all seven need --
// the activation signals, the country map, the three windows, the whole-word
// vocabulary, the near-miss policy, the table constants and the reference
// labels -- so nothing here is hand-written registry data and no window is
// hard-coded.
//
//   1. ACTIVATE   a country's patterns run only when one of its signals fires.
//   1a. ALWAYS ON  a pattern the bundle marks alwaysOn (since 1.2.0: Australia's
//                  au_tfn, au_abn, au_medicare) runs on every document regardless
//                  of rule 1, before the activated country patterns.
//   2. MATCH      the regex, case-sensitively, globally.
//   3. KEYWORD    whole-word (symmetric ContextWindow) or column verdict or the
//                 ASYMMETRIC substring window (60 before, 40 after); then 7b
//                 may close the gate again.
//   4. CHECKSUM   when required. Advisory checksums never reject.
//   5. SUPERSEDE  a match containing every range it overlaps takes them.
//   6. NEAR MISS  a checksum-failing identifier is redacted generically.
//   7. COLUMN     in a delimited table a bare value cell is judged by its header.
//   7b. NEAREST LABEL  a closer commercial label closes the gate.
//
// Still cloud-only, by design: the universal (L0) patterns, the slot, context,
// gravity and name layers, industry profiles and org configuration.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Tork.Governance.Pii;

namespace TorkGovernance.CountryPii;

public static class PiiCountry
{
    /// <summary>One country identifier found in the content.</summary>
    public sealed record CountryPiiMatch(
        string Name, string Country, string Label, string Type,
        string Redaction, int StartIndex, int EndIndex);

    /// <summary>A span of the original text and the token that replaces it.</summary>
    public sealed record RedactionSpan
    {
        public int StartIndex { get; init; }
        public int EndIndex { get; init; }
        public string Redaction { get; init; } = string.Empty;
    }

    /// <summary>Matches, plus the caller's own L0 ranges that rule 5 superseded.</summary>
    public sealed record CountryPiiResult(
        IReadOnlyList<CountryPiiMatch> Matches,
        IReadOnlyList<(int Start, int End)> SupersededRanges);

    /// <summary>Characters before a match that count as nearby for the substring gate.</summary>
    public const int KeywordWindowBefore = PiiRegistry.KeywordWindowBefore;

    /// <summary>Characters after. Deliberately NOT the same number as before.</summary>
    public const int KeywordWindowAfter = PiiRegistry.KeywordWindowAfter;

    /// <summary>The symmetric window: whole-word keywords and the near-miss gate.</summary>
    public const int ContextWindow = PiiRegistry.ContextWindow;

    /// <summary>The bundle this SDK shipped.</summary>
    public const string RegistryVersion = PiiRegistry.Version;

    /// <summary>The bundle content hash, which answers "did the data change".</summary>
    public const string ContentHash = PiiRegistry.ContentHash;

    private static readonly Dictionary<string, Regex> Compiled =
        PiiRegistry.Patterns.ToDictionary(p => p.Name, p => new Regex(p.Regex, RegexOptions.Compiled));

    private static readonly Dictionary<string, PiiPattern> ByName =
        PiiRegistry.Patterns.ToDictionary(p => p.Name, p => p);

    private static readonly List<Regex> CompiledSignals = PiiRegistry.Signals
        .Select(s => new Regex(
            s.Regex,
            s.Flags.Contains('i') ? RegexOptions.Compiled | RegexOptions.IgnoreCase : RegexOptions.Compiled))
        .ToList();

    private static readonly List<string> SignalOrder =
        PiiRegistry.Signals.Select(s => s.Country).Distinct().ToList();

    private static readonly Dictionary<string, string[]> CountryPatterns =
        PiiRegistry.Countries.ToDictionary(c => c.Code, c => c.Patterns);

    private static readonly HashSet<string> GenericSet = new(PiiRegistry.GenericIdKeywords);

    private static readonly string[] NationalIdKeywords =
        PiiRegistry.GenericIdKeywords.Concat(PiiRegistry.LocalIdKeywords).ToArray();

    private static bool IsAlnum(char c) => char.IsAsciiLetterOrDigit(c);

    /// <summary>A pattern's whole vocabulary: the substring keywords and the whole-word ones.</summary>
    private static string[] AllKeywordsOf(PiiPattern p) =>
        p.WholeWordKeywords.Length == 0 ? p.Keywords : p.Keywords.Concat(p.WholeWordKeywords).ToArray();

    /// <summary>The half of a vocabulary that names ONE country's identifier.</summary>
    private static string[] SpecificKeywords(IEnumerable<string> keywords) =>
        keywords.Where(k => !GenericSet.Contains(k)).ToArray();

    private static string WindowBefore(string content, int start, int width)
    {
        var lo = Math.Max(0, start - width);
        return content.Substring(lo, start - lo).ToLowerInvariant();
    }

    private static string WindowAfter(string content, int end, int width)
    {
        var hi = Math.Min(content.Length, end + width);
        return content.Substring(end, hi - end).ToLowerInvariant();
    }

    private static string WindowAround(string content, int start, int end, int width)
    {
        var lo = Math.Max(0, start - width);
        var hi = Math.Min(content.Length, end + width);
        return content.Substring(lo, hi - lo).ToLowerInvariant();
    }

    /// <summary>Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it.</summary>
    private static bool HasNearbyContext(string content, int start, int end, IReadOnlyList<string> keywords)
    {
        var before = WindowBefore(content, start, KeywordWindowBefore);
        var after = WindowAfter(content, end, KeywordWindowAfter);
        return keywords.Any(k => before.Contains(k, StringComparison.Ordinal) || after.Contains(k, StringComparison.Ordinal));
    }

    /// <summary>Symmetric ContextWindow either side, substring. Used by rule 6.</summary>
    private static bool HasContextAround(string content, int start, int end, IReadOnlyList<string> keywords)
    {
        var w = WindowAround(content, start, end, ContextWindow);
        return keywords.Any(k => w.Contains(k, StringComparison.Ordinal));
    }

    /// <summary>
    /// Rule 3, whole-word half: symmetric ContextWindow, a boundary each side,
    /// a boundary being "not a letter or digit".
    /// <para>
    /// This is the gate Indonesia needs: <c>nik</c> sits inside <i>teknik</i>,
    /// <i>elektronik</i>, <i>klinik</i> and <i>pabrik</i>, so a substring test
    /// would open the gate on a sales ledger.
    /// </para>
    /// </summary>
    public static bool HasWholeWordContextAround(string content, int start, int end, IReadOnlyList<string>? words)
    {
        if (words is null || words.Count == 0) return false;
        var w = WindowAround(content, start, end, ContextWindow);
        foreach (var word in words)
        {
            var from = 0;
            while (from <= w.Length - word.Length)
            {
                var i = w.IndexOf(word, from, StringComparison.Ordinal);
                if (i < 0) break;
                var beforeOk = i == 0 || !IsAlnum(w[i - 1]);
                var j = i + word.Length;
                var afterOk = j >= w.Length || !IsAlnum(w[j]);
                if (beforeOk && afterOk) return true;
                from = i + 1;
            }
        }
        return false;
    }

    private static bool DocumentHasWholeWord(string content, IReadOnlyList<string>? words) =>
        words is not null && words.Count > 0 && HasWholeWordContextAround(content, 0, content.Length, words);

    // ── rule 1: activation ──────────────────────────────────────────────────

    /// <summary>The countries this text activates, in the bundle's signal order.</summary>
    public static IReadOnlyList<string> InferRegions(string content)
    {
        var regions = new List<string>();
        var lower = content.ToLowerInvariant();
        foreach (var code in SignalOrder)
        {
            for (var i = 0; i < PiiRegistry.Signals.Count; i++)
            {
                var s = PiiRegistry.Signals[i];
                if (s.Country != code) continue;
                if (!CompiledSignals[i].IsMatch(content)) continue;

                var bySubstring = s.Keywords.Length > 0 &&
                    s.Keywords.Any(k => lower.Contains(k, StringComparison.Ordinal));
                var byWholeWord = DocumentHasWholeWord(content, s.WholeWordKeywords);
                // Both lists empty means the shape alone is distinctive enough.
                if ((s.Keywords.Length > 0 || s.WholeWordKeywords.Length > 0) && !bySubstring && !byWholeWord)
                    continue;

                var target = string.IsNullOrEmpty(s.Activates) ? code : s.Activates;
                if (!regions.Contains(target)) regions.Add(target);
                break; // one signal per country is enough
            }
        }
        return regions;
    }

    /// <summary>The patterns those regions switch on, de-duplicated, in registry order.</summary>
    public static IReadOnlyList<PiiPattern> PatternsForRegions(IEnumerable<string> regions)
    {
        var outp = new List<PiiPattern>();
        var seen = new HashSet<string>();
        foreach (var code in regions)
        {
            if (!CountryPatterns.TryGetValue(code.ToUpperInvariant(), out var names)) continue;
            foreach (var name in names)
            {
                if (!seen.Add(name)) continue;
                if (ByName.TryGetValue(name, out var p)) outp.Add(p);
            }
        }
        return outp;
    }

    /// <summary>
    /// Rule 1a: patterns marked <c>alwaysOn</c> in the bundle (since 1.2.0: Australia's
    /// au_tfn, au_abn, au_medicare) run on every document, whatever rule 1 (region
    /// activation) returned, and run BEFORE the activated country patterns so an
    /// activated pattern can still supersede one of them under rule 5.
    /// </summary>
    private static readonly IReadOnlyList<PiiPattern> AlwaysOnPatterns =
        PiiRegistry.Patterns.Where(p => p.AlwaysOn).ToList();

    private static IReadOnlyList<PiiPattern> WithAlwaysOn(IReadOnlyList<PiiPattern> regionPatterns)
    {
        if (AlwaysOnPatterns.Count == 0) return regionPatterns;
        var outp = new List<PiiPattern>(AlwaysOnPatterns);
        var seen = new HashSet<string>(AlwaysOnPatterns.Select(p => p.Name));
        foreach (var p in regionPatterns)
            if (seen.Add(p.Name)) outp.Add(p);
        return outp;
    }

    // ── rule 7: the column is the context ───────────────────────────────────

    private sealed record TableScope(int Start, int End, string Header, int RowStart, int RowEnd);

    private static readonly Regex HeaderHasLetter = new(@"[A-Za-zÀ-￿]", RegexOptions.Compiled);
    private static readonly Regex HeaderAllNumeric = new(@"^\+?[\d\s.\-/]+$", RegexOptions.Compiled);
    private static readonly Regex HeaderSentence = new(@"[.?!]", RegexOptions.Compiled);
    private static readonly Regex WhitespaceRun = new(@"\s+", RegexOptions.Compiled);

    private static bool LooksLikeHeader(string[] cells, string delimiter)
    {
        var minimum = delimiter == "," ? PiiRegistry.TableMinCommaColumns : 2;
        if (cells.Length < minimum) return false;
        foreach (var c in cells)
        {
            var t = c.Trim();
            if (t.Length == 0 || t.Length > PiiRegistry.TableMaxHeaderLength) return false;
            if (!HeaderHasLetter.IsMatch(t)) return false;
            if (HeaderAllNumeric.IsMatch(t)) return false;
            if (HeaderSentence.IsMatch(t)) return false;
            if (WhitespaceRun.Split(t).Length > PiiRegistry.TableMaxHeaderWords) return false;
        }
        return true;
    }

    /// <summary>The cells of <paramref name="content"/>, when it is a delimited table.</summary>
    public static bool IsTable(string content) => TableScopes(content).Count > 0;

    private static IReadOnlyList<TableScope> TableScopes(string content)
    {
        var lines = content.Split('\n');
        if (lines.Length < PiiRegistry.TableMinRows) return Array.Empty<TableScope>();

        var offsets = new int[lines.Length];
        var at = 0;
        for (var i = 0; i < lines.Length; i++) { offsets[i] = at; at += lines[i].Length + 1; }

        foreach (var delimiter in PiiRegistry.TableDelimiters)
        {
            var headerCells = lines[0].Split(delimiter);
            if (!LooksLikeHeader(headerCells, delimiter)) continue;
            var width = headerCells.Length;

            var dataRows = new List<int>();
            for (var i = 1; i < lines.Length; i++)
            {
                if (lines[i].Trim().Length == 0) continue;
                if (lines[i].Split(delimiter).Length != width) return Array.Empty<TableScope>();
                dataRows.Add(i);
            }
            if (dataRows.Count < PiiRegistry.TableMinRows - 1) continue;

            var scopes = new List<TableScope>();
            foreach (var row in dataRows)
            {
                var cells = lines[row].Split(delimiter);
                var rowStart = offsets[row];
                var rowEnd = rowStart + lines[row].Length;
                var cellStart = rowStart;
                for (var col = 0; col < width; col++)
                {
                    scopes.Add(new TableScope(cellStart, cellStart + cells[col].Length,
                        headerCells[col].Trim().ToLowerInvariant(), rowStart, rowEnd));
                    cellStart += cells[col].Length + delimiter.Length;
                }
            }
            return scopes;
        }
        return Array.Empty<TableScope>();
    }

    /// <summary>A whole-word match, not a substring.</summary>
    private static bool HeaderNames(string header, IReadOnlyList<string> keywords)
    {
        foreach (var kw in keywords)
        {
            var i = header.IndexOf(kw, StringComparison.Ordinal);
            if (i < 0) continue;
            var beforeOk = i == 0 || !IsAlnum(header[i - 1]);
            var j = i + kw.Length;
            var afterOk = j >= header.Length || !IsAlnum(header[j]);
            if (beforeOk && afterOk) return true;
        }
        return false;
    }

    /// <summary>null when the window should be consulted as usual.</summary>
    private static bool? ColumnVerdict(string content, IReadOnlyList<TableScope> scopes, int start, int end,
        IReadOnlyList<string> all, IReadOnlyList<string> specific)
    {
        if (scopes.Count == 0) return null;
        var cell = scopes.FirstOrDefault(s => start >= s.Start && end <= s.End);
        if (cell is null) return null;
        // A cell whose own row names the identifier is prose in a delimited block.
        var rowText = content.Substring(cell.RowStart, cell.RowEnd - cell.RowStart).ToLowerInvariant();
        if (all.Any(k => rowText.Contains(k, StringComparison.Ordinal))) return null;
        return specific.Count > 0 && HeaderNames(cell.Header, specific);
    }

    // ── rule 7b: nearest label wins ─────────────────────────────────────────

    private static int? ClosestBefore(string before, IReadOnlyList<string> keywords)
    {
        int? best = null;
        foreach (var kw in keywords)
        {
            var i = before.LastIndexOf(kw, StringComparison.Ordinal);
            if (i < 0) continue;
            var d = before.Length - (i + kw.Length);
            if (best is null || d < best) best = d;
        }
        return best;
    }

    private static int? ClosestAfter(string after, IReadOnlyList<string> keywords)
    {
        int? best = null;
        foreach (var kw in keywords)
        {
            var i = after.IndexOf(kw, StringComparison.Ordinal);
            if (i < 0) continue;
            if (best is null || i < best) best = i;
        }
        return best;
    }

    /// <summary>
    /// Whether the number is labelled as a commercial reference more closely
    /// than as an identifier. It can only ever close a gate, never open one.
    /// </summary>
    public static bool LabelledAsReference(string content, int start, int end, IReadOnlyList<string>? identifierKeywords)
    {
        var before = WindowBefore(content, start, PiiRegistry.LabelWindow);
        var reference = ClosestBefore(before, PiiRegistry.ReferenceLabels);
        if (reference is null || reference > PiiRegistry.LabelReach) return false;
        if (identifierKeywords is null || identifierKeywords.Count == 0) return true;

        var idBefore = ClosestBefore(before, identifierKeywords);
        if (idBefore is not null && idBefore <= reference) return false;
        var after = WindowAfter(content, end, PiiRegistry.LabelWindow);
        var idAfter = ClosestAfter(after, identifierKeywords);
        if (idAfter is not null && idAfter <= reference) return false;
        return true;
    }

    // ── the pass ────────────────────────────────────────────────────────────

    /// <summary>The span with leading and trailing non-alphanumeric characters removed.</summary>
    public static (int Start, int End) TrimmedCore(string content, int start, int end)
    {
        var s = start;
        var e = end;
        while (s < e && !IsAlnum(content[s])) s++;
        while (e > s && !IsAlnum(content[e - 1])) e--;
        return s == e ? (start, end) : (s, e);
    }

    /// <summary>Country matches for <paramref name="content"/>.</summary>
    public static IReadOnlyList<CountryPiiMatch> Detect(string content, IReadOnlyList<PiiPattern>? patterns = null) =>
        DetectWithRanges(content, patterns).Matches;

    /// <summary>
    /// The full pass. Pass your own L0 spans as <paramref name="existingRanges"/>
    /// so rule 5 can supersede them, and read <c>SupersededRanges</c> back.
    /// </summary>
    public static CountryPiiResult DetectWithRanges(string content, IReadOnlyList<PiiPattern>? patterns = null,
        IReadOnlyList<(int Start, int End)>? existingRanges = null)
    {
        var active = patterns ?? WithAlwaysOn(PatternsForRegions(InferRegions(content)));
        if (active.Count == 0)
            return new CountryPiiResult(Array.Empty<CountryPiiMatch>(), Array.Empty<(int, int)>());

        var tables = TableScopes(content);
        var activeExisting = new List<(int Start, int End)>(existingRanges ?? Array.Empty<(int, int)>());
        var superseded = new List<(int Start, int End)>();
        var claimed = new List<(int Start, int End)>();
        var found = new List<CountryPiiMatch>();
        var nearMisses = new List<(int Start, int End)>();

        foreach (var pattern in active)
        {
            foreach (Match m in Compiled[pattern.Name].Matches(content))
            {
                if (m.Length == 0) continue;
                var start = m.Index;
                var end = start + m.Length;

                // Rules 3, 7 and 7b.
                if (pattern.RequiresKeyword && pattern.Keywords.Length > 0)
                {
                    var all = AllKeywordsOf(pattern);
                    bool ok;
                    if (HasWholeWordContextAround(content, start, end, pattern.WholeWordKeywords))
                    {
                        ok = true;
                    }
                    else
                    {
                        var column = ColumnVerdict(content, tables, start, end, all, SpecificKeywords(all));
                        ok = column ?? HasNearbyContext(content, start, end, pattern.Keywords);
                    }
                    if (!ok) continue;
                    if (LabelledAsReference(content, start, end, pattern.Keywords)) continue;
                }

                // Rule 4, and rule 6's candidate.
                if (pattern.ChecksumRequired && pattern.Checksum is not null &&
                    PiiChecksums.Functions.TryGetValue(pattern.Checksum, out var fn) && !fn(m.Value))
                {
                    if (pattern.NearMissFallback)
                    {
                        var extra = pattern.NearMissKeywords.Length > 0 ? pattern.NearMissKeywords : pattern.Keywords;
                        var vocabulary = extra.Length > 0
                            ? NationalIdKeywords.Concat(extra).ToArray()
                            : NationalIdKeywords;
                        if (HasContextAround(content, start, end, vocabulary)) nearMisses.Add((start, end));
                    }
                    continue;
                }

                // Rule 5.
                var overlapping = activeExisting.Concat(claimed)
                    .Where(r => start < r.End && end > r.Start).ToList();
                if (overlapping.Count > 0)
                {
                    var supersedesAll = overlapping.All(r =>
                    {
                        var (cs, ce) = TrimmedCore(content, r.Start, r.End);
                        return start <= cs && end >= ce;
                    });
                    if (!supersedesAll) continue;
                    foreach (var o in overlapping)
                    {
                        if (activeExisting.Remove(o)) superseded.Add(o);
                        claimed.Remove(o);
                        found.RemoveAll(f => f.StartIndex == o.Start && f.EndIndex == o.End);
                    }
                }

                claimed.Add((start, end));
                found.Add(new CountryPiiMatch(pattern.Name, pattern.Country, pattern.Label,
                    pattern.Type, pattern.Redaction, start, end));
            }
        }

        // Rule 6, last: a near miss can only ever fill a hole.
        var taken = activeExisting.Concat(claimed).ToList();
        foreach (var c in nearMisses)
        {
            if (taken.Any(r => c.Start < r.End && c.End > r.Start)) continue;
            taken.Add(c);
            found.Add(new CountryPiiMatch(PiiRegistry.NearMissType, string.Empty, "NATIONAL_ID",
                PiiRegistry.NearMissType, PiiRegistry.NearMissRedaction, c.Start, c.End));
        }

        return new CountryPiiResult(found.OrderBy(f => f.StartIndex).ToList(), superseded);
    }

    /// <summary>Turn country matches into redaction spans.</summary>
    public static IReadOnlyList<RedactionSpan> RedactionSpansOf(IEnumerable<CountryPiiMatch> matches) =>
        matches.Select(m => new RedactionSpan { StartIndex = m.StartIndex, EndIndex = m.EndIndex, Redaction = m.Redaction }).ToList();

    /// <summary>
    /// Replace every span with its redaction, right to left.
    /// <para>
    /// Right to left is what keeps the earlier indices valid, and splicing whole
    /// spans in one pass is what guarantees no partial redaction: a digit can
    /// never be left standing beside a redaction token, because nothing is ever
    /// matched against text a previous replacement has already rewritten.
    /// </para>
    /// </summary>
    public static string ApplyRedactions(string text, IReadOnlyList<RedactionSpan> spans)
    {
        if (spans.Count == 0) return text;
        var ordered = spans.OrderBy(s => s.StartIndex).ToList();
        var outp = text;
        for (var i = ordered.Count - 1; i >= 0; i--)
        {
            var s = ordered[i];
            outp = outp[..s.StartIndex] + s.Redaction + outp[s.EndIndex..];
        }
        return outp;
    }
}
