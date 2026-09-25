// Country-layer parity tests.
//
// The fixtures are generated from the cloud's own evidence, not written here:
//
//   pii_unit_cases.json  one valid sample per registry pattern, a
//                        checksum-broken variant for each pattern whose
//                        checksum is a gate, and the Indonesian boundary cases.
//   pii_vectors.json     all 2,092 inputs of the cloud's golden snapshot: every
//                        country-corpus sentence for all 249 ISO jurisdictions,
//                        and the whole 1,523-line business false-positive corpus.
//
// expectedOutput is the COUNTRY LAYER alone. Where the cloud's own output
// differs, the case carries cloudOutput and a divergence naming the cause.

using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Tork.Governance.Pii;
using TorkGovernance.CountryPii;
using Xunit;

// The bundle declares a `PiiCountry` RECORD (one country profile) in
// Tork.Governance.Pii, and this SDK's country engine is a `PiiCountry` CLASS in
// TorkGovernance.CountryPii. The alias picks the engine; the record is only
// ever reached through PiiRegistry.Countries, which is typed.
using PiiCountry = TorkGovernance.CountryPii.PiiCountry;

namespace TorkGovernance.Tests;

public sealed record UnitCase(
    [property: JsonPropertyName("pattern")] string Pattern,
    [property: JsonPropertyName("country")] string Country,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("redaction")] string Redaction,
    [property: JsonPropertyName("input")] string Input,
    [property: JsonPropertyName("sample")] string Sample,
    [property: JsonPropertyName("expectDetected")] bool ExpectDetected);

public sealed record Vector(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("input")] string Input,
    [property: JsonPropertyName("expectedOutput")] string ExpectedOutput,
    [property: JsonPropertyName("expectedRegions")] string[] ExpectedRegions,
    [property: JsonPropertyName("expectedLabels")] string[] ExpectedLabels,
    [property: JsonPropertyName("expectedNames")] string[] ExpectedNames,
    [property: JsonPropertyName("cloudOutput")] string? CloudOutput,
    [property: JsonPropertyName("divergence")] string? Divergence);

public sealed record VectorFile(
    [property: JsonPropertyName("bundleVersion")] string BundleVersion,
    [property: JsonPropertyName("contentHash")] string ContentHash,
    [property: JsonPropertyName("cases")] Vector[] Cases);

public class PiiCountryTests
{
    private const string Nik = "3171010101900001";

    private static readonly VectorFile V =
        JsonSerializer.Deserialize<VectorFile>(File.ReadAllText(Path.Combine("fixtures", "pii_vectors.json")))!;

    private static readonly UnitCase[] Units =
        JsonSerializer.Deserialize<UnitCase[]>(File.ReadAllText(Path.Combine("fixtures", "pii_unit_cases.json")))!;

    private static string Redact(string s) =>
        PiiCountry.ApplyRedactions(s, PiiCountry.RedactionSpansOf(PiiCountry.Detect(s)));

    // ── the bundle ──────────────────────────────────────────────────────────

    [Fact]
    public void IsTheVersionAndContentTheFixturesWereGeneratedFrom()
    {
        Assert.Equal(V.BundleVersion, PiiRegistry.Version);
        Assert.Equal(V.ContentHash, PiiRegistry.ContentHash);
    }

    [Fact]
    public void Carries54PatternsAcross24ProfilesWith51Signals()
    {
        // 54 = the 51 bundle 1.1.0 shipped plus the 3 alwaysOn patterns 1.2.0
        // added (au_tfn, au_abn, au_medicare) — see rule 1a below. Countries
        // and signals are unchanged: the three were already named by
        // checksums.json and reachable via AU's signals, just absent from
        // `patterns` until now.
        Assert.Equal(54, PiiRegistry.Patterns.Count);
        Assert.Equal(24, PiiRegistry.Countries.Count);
        Assert.Equal(51, PiiRegistry.Signals.Count);
    }

    [Fact]
    public void CoversIndonesiaAddedIn110()
    {
        var id = PiiRegistry.Countries.FirstOrDefault(c => c.Code == "ID");
        Assert.NotNull(id);
        Assert.Contains("id_nik", id!.Patterns);
        var nik = PiiRegistry.Patterns.First(p => p.Name == "id_nik");
        Assert.Equal("NIK", nik.Label);
        Assert.Contains("nik", nik.WholeWordKeywords);
    }

    [Fact]
    public void ReadsItsWindowsFromTheBundleAndTheyAreNotAllTheSame()
    {
        Assert.Equal(60, PiiCountry.KeywordWindowBefore);
        Assert.Equal(40, PiiCountry.KeywordWindowAfter);
        Assert.Equal(60, PiiCountry.ContextWindow);
        Assert.NotEqual(PiiCountry.KeywordWindowBefore, PiiCountry.KeywordWindowAfter);
    }

    [Fact]
    public void NamesAChecksumFunctionForEveryPatternThatDeclaresOne()
    {
        foreach (var p in PiiRegistry.Patterns.Where(p => p.Checksum is not null))
            Assert.True(PiiChecksums.Functions.ContainsKey(p.Checksum!), $"{p.Name} -> {p.Checksum}");
    }

    [Fact]
    public void UsesOnlyThePortableRegexSubset()
    {
        var forbidden = new (string Bad, string Why)[]
        {
            ("(?=", "lookahead"), ("(?!", "negative lookahead"), ("(?<=", "lookbehind"),
            ("(?<!", "negative lookbehind"), ("\\p{", "unicode property escape"), ("(?>", "atomic group"),
        };
        var sources = PiiRegistry.Patterns.Select(p => p.Regex).Concat(PiiRegistry.Signals.Select(s => s.Regex));
        foreach (var src in sources)
            foreach (var (bad, why) in forbidden)
                Assert.False(src.Contains(bad, StringComparison.Ordinal), $"{src} uses {why}");
    }

    // ── per-pattern unit cases ──────────────────────────────────────────────

    [Fact]
    public void PerPatternUnitCases()
    {
        Assert.NotEmpty(Units);
        foreach (var c in Units)
        {
            var p = PiiRegistry.Patterns.FirstOrDefault(x => x.Name == c.Pattern);
            Assert.True(p is not null, $"{c.Pattern} is not in the bundle");
            var hit = PiiCountry.Detect(c.Input, new[] { p! }).FirstOrDefault(m => m.Name == c.Pattern);
            if (c.ExpectDetected)
            {
                Assert.True(hit is not null, $"expected {c.Pattern} to match {c.Input}");
                Assert.Equal(c.Sample, c.Input[hit!.StartIndex..hit.EndIndex]);
                Assert.Equal(c.Redaction, hit.Redaction);
            }
            else
            {
                Assert.True(hit is null, $"expected {c.Pattern} NOT to match {c.Input}");
            }
        }
    }

    // ── golden-snapshot parity ──────────────────────────────────────────────

    [Fact]
    public void ReproducesTheCloudOnEveryCorpusVector()
    {
        var failures = new List<string>();
        var checked_ = 0;
        foreach (var c in V.Cases.Where(c => c.Kind != "business-fp"))
        {
            checked_++;
            var matches = PiiCountry.Detect(c.Input);
            var outp = PiiCountry.ApplyRedactions(c.Input, PiiCountry.RedactionSpansOf(matches));
            if (!PiiCountry.InferRegions(c.Input).SequenceEqual(c.ExpectedRegions)) failures.Add($"{c.Id} activation");
            if (outp != c.ExpectedOutput) failures.Add($"{c.Id} redaction");
            if (!matches.Select(m => m.Label).Distinct().SequenceEqual(c.ExpectedLabels)) failures.Add($"{c.Id} labels");
            if (!matches.Select(m => m.Name).Distinct().SequenceEqual(c.ExpectedNames)) failures.Add($"{c.Id} names");
        }
        Assert.True(checked_ > 500, $"only {checked_} corpus vectors");
        Assert.Empty(failures);
    }

    [Fact]
    public void AddsNoFalsePositiveToTheBusinessCorpus()
    {
        var business = V.Cases.Where(c => c.Kind == "business-fp").ToList();
        Assert.True(business.Count > 1500);
        var bad = business.Where(c => PiiCountry.Detect(c.Input).Count > 0).Select(c => c.Id).ToList();
        Assert.Empty(bad);
        var drift = business.Where(c => !PiiCountry.InferRegions(c.Input).SequenceEqual(c.ExpectedRegions))
            .Select(c => c.Id).ToList();
        Assert.Empty(drift);
    }

    [Fact]
    public void DivergesFromTheCloudOnlyForTheStatedL0Reason()
    {
        // Bundle 1.2.0 closed the AU bundle gap (rule 1a): au_tfn, au_abn and
        // au_medicare are now alwaysOn patterns, so every case that used to
        // diverge with "BUNDLE GAP: ..." now reproduces the cloud exactly.
        // The only cause left is L0 — inputs where no country activates and
        // the cloud's redaction came from the universal layer this bundle
        // deliberately excludes.
        var diverged = V.Cases.Where(c => c.Divergence is not null).ToList();
        foreach (var c in diverged)
            Assert.True(c.Divergence!.StartsWith("L0:"), $"{c.Id}: unexplained divergence ({c.Divergence})");
        var gaps = diverged.Where(c => c.Divergence!.StartsWith("BUNDLE GAP:"))
            .Select(c => c.Id.Split('/')[1]).Distinct().OrderBy(x => x).ToList();
        Assert.Empty(gaps);
    }

    [Fact]
    public void NothingIsEverPartiallyRedacted()
    {
        var bad = new Regex(@"\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d");
        foreach (var c in V.Cases)
        {
            var matches = PiiCountry.Detect(c.Input);
            var outp = PiiCountry.ApplyRedactions(c.Input, PiiCountry.RedactionSpansOf(matches));
            Assert.False(bad.IsMatch(outp), $"{c.Id}: {outp}");
            foreach (var m in matches)
                Assert.DoesNotContain(c.Input[m.StartIndex..m.EndIndex], outp, StringComparison.Ordinal);
        }
    }

    // ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────

    [Fact]
    public void DetectsTheShortSpellingWhichIsAWholeWordKeywordOnly()
    {
        var s = $"NIK {Nik} untuk pendaftaran rekening di Jakarta, Indonesia.";
        Assert.Equal(new[] { "ID" }, PiiCountry.InferRegions(s));
        Assert.Equal("NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.", Redact(s));
    }

    [Fact]
    public void DetectsTheLongSpellingWhichIsAnOrdinarySubstringKeyword() =>
        Assert.Contains("[NIK_REDACTED]", Redact($"Nomor Induk Kependudukan {Nik} untuk pendaftaran."));

    [Theory]
    [InlineData("teknik")]
    [InlineData("elektronik")]
    [InlineData("klinik")]
    [InlineData("pabrik")]
    [InlineData("piknik")]
    public void NikInsideAnOrdinaryIndonesianWordDoesNotOpenTheGate(string word) =>
        Assert.Empty(PiiCountry.Detect($"Faktur {word} {Nik} untuk pelanggan."));

    [Fact]
    public void ABareNikIsNotRedacted() => Assert.Empty(PiiCountry.Detect(Nik));

    // ── the rules 1.1.0 added to the SDK half of the contract ───────────────

    [Fact]
    public void Rule6ChecksumFailingIdentifierIsRedactedGenerically()
    {
        var outp = Redact("South African ID number 8001015009088 for the FICA check.");
        Assert.DoesNotContain("8001015009088", outp, StringComparison.Ordinal);
        Assert.Contains("[NATIONAL_ID_REDACTED]", outp, StringComparison.Ordinal);
    }

    [Fact]
    public void Rule7ColumnHeaderIsTheContextForABareValueCell()
    {
        var csv = string.Join("\n", "Name,CNIC,City", "Ali,42201-1234567-1,Karachi",
            "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan");
        Assert.True(PiiCountry.IsTable(csv));
        Assert.DoesNotContain("42201-1234567-1", Redact(csv), StringComparison.Ordinal);
    }

    [Fact]
    public void Rule7GenericHeaderDoesNotActAsContext()
    {
        var csv = string.Join("\n", "Name,Order ID Number,City", "Ali,42201-1234567-1,Karachi",
            "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan");
        Assert.Empty(PiiCountry.Detect(csv));
    }

    [Fact]
    public void Rule7bCloserCommercialLabelClosesTheGate()
    {
        const string s = "Please do not send your CNIC. Use the job number 4220112345671.";
        var at = s.IndexOf("4220112345671", StringComparison.Ordinal);
        Assert.True(PiiCountry.LabelledAsReference(s, at, at + 13, new[] { "cnic" }));
        Assert.Contains("4220112345671", Redact(s), StringComparison.Ordinal);
    }

    [Fact]
    public void Rule7bCanOnlyCloseAGateNeverOpenOne() =>
        Assert.Empty(PiiCountry.Detect("Order 12345678901234 with no identifier word anywhere."));

    [Fact]
    public void Rule5CountryMatchSupersedesAWiderL0Range()
    {
        const string s = "CPF 529.982.247-25 para a nota fiscal no Brasil.";
        var at = s.IndexOf("529.982.247-25", StringComparison.Ordinal);
        var res = PiiCountry.DetectWithRanges(s, null, new[] { (at - 1, at + 14) });
        Assert.Contains(res.Matches, m => m.Name == "br_cpf");
        Assert.Single(res.SupersededRanges);
    }

    [Fact]
    public void WholeWordMatchingRespectsBoundaries()
    {
        Assert.True(PiiCountry.HasWholeWordContextAround("nik 123", 4, 7, new[] { "nik" }));
        Assert.False(PiiCountry.HasWholeWordContextAround("teknik 123", 7, 10, new[] { "nik" }));
    }

    // ── Australia, the alwaysOn rule (1a) bundle 1.2.0 added ────────────────
    //
    // au_tfn, au_abn and au_medicare are the first patterns the bundle marks
    // alwaysOn: they run on every document regardless of rule 1's country
    // activation, because none of Australia's own signals fire on a bare TFN,
    // ABN or Medicare number (README, rule 1a). au_tfn's and au_abn's
    // checksums are REQUIRED by checksums.json; au_medicare's is ADVISORY.

    [Fact]
    public void ValidTfnIsDetectedAndRedacted()
    {
        // "tax file" is itself one of AU's own activation signals, so this
        // one DOES activate AU under rule 1 too -- the ABN case just below is
        // the one rule 1a actually exists for (see its own comment).
        const string s = "My tax file number is 876 543 210 for the ATO return.";
        Assert.Equal(new[] { "AU" }, PiiCountry.InferRegions(s));
        Assert.Equal("My tax file number is [TFN_REDACTED] for the ATO return.", Redact(s));
    }

    [Fact]
    public void ValidAbnIsDetectedAndRedactedWithoutAuActivating()
    {
        const string s = "Supplier ABN 51 824 753 556 appears on the Australian invoice.";
        Assert.DoesNotContain("AU", PiiCountry.InferRegions(s));
        Assert.Equal("Supplier ABN [ABN_REDACTED] appears on the Australian invoice.", Redact(s));
    }

    [Fact]
    public void ChecksumFailingTfnFallsBackToTheGenericNearMiss()
    {
        // au_tfn's kind is tax_id (a near-miss kind) and its checksum is
        // required, so a bad check digit is still redacted, just generically.
        const string s = "My tax file number is 876 543 211 for the ATO return.";
        Assert.Equal("My tax file number is [NATIONAL_ID_REDACTED] for the ATO return.", Redact(s));
    }

    [Fact]
    public void ChecksumFailingAbnIsRejectedOutright()
    {
        // au_abn's kind is company, not a near-miss kind, so a failed
        // required checksum drops the candidate entirely rather than
        // falling back — unlike au_tfn just above.
        const string s = "Supplier ABN 51 824 753 557 appears on the Australian invoice.";
        Assert.Equal(s, Redact(s));
    }

    [Fact]
    public void ValidMedicareIsDetectedWithItsKeyword()
    {
        const string s = "Patient Medicare number 2123 45670 1 for the bulk-billed visit.";
        Assert.Equal("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.", Redact(s));
    }

    [Fact]
    public void ChecksumFailingMedicareIsStillRedactedBecauseItsGateIsAdvisoryOnly()
    {
        // au_medicare's checksum is advisory (checksumRequired: false), so a
        // bad check digit never blocks detection — unlike au_tfn and au_abn.
        const string s = "Patient Medicare number 2123 45671 1 for the bulk-billed visit.";
        Assert.Equal("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.", Redact(s));
    }

    [Fact]
    public void Rule1aPatternsRunBeforeActivatedCountryPatternsSoRule5CanSupersedeThem()
    {
        var alwaysOn = PiiRegistry.Patterns.Where(p => p.AlwaysOn).Select(p => p.Name).ToList();
        Assert.Equal(new[] { "au_tfn", "au_abn", "au_medicare" }, alwaysOn);
    }
}
