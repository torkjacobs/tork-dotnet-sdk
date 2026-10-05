using TorkGovernance.Core;

namespace TorkGovernance.Tests;

/// <summary>
/// STEP 0 — PARITY FIRST (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS,
/// P1). Every PII type this SDK declares for tool-result scanning must have
/// a live pattern. JS, Go and (per the porting brief) a third SDK were each
/// found to declare a PII type with no corresponding pattern -- most
/// concretely the Go SDK, whose PIIType const block once listed 10 values
/// while its pattern table implemented only 7 (passport, drivers_license
/// and bank_account passed through undetected).
///
/// Pii.Patterns in this SDK is deliberately a SINGLE table serving as both
/// declaration and implementation (see Pii.cs), which prevents this bug
/// class by construction: there is no second list of "declared" type names
/// that can drift out of sync with the patterns. This test's job is
/// therefore to pin that single table against the external reference
/// (tork-js-sdk/src/pii.ts's PII_PATTERNS) it must stay byte-identical to --
/// so a future edit that adds a type without a pattern, drops a type, or
/// changes a label away from JS parity fails loudly here instead of
/// shipping silently.
/// </summary>
public class ParityTests
{
    /// <summary>The JS SDK's Tier-1 PII vocabulary (pii.ts PII_PATTERNS), in
    /// its declared order, with JS-identical redaction labels.</summary>
    private static readonly (string Type, string Redaction)[] JsReferenceVocabulary =
    {
        ("ssn", "[SSN_REDACTED]"),
        ("credit_card", "[CARD_REDACTED]"),
        ("email", "[EMAIL_REDACTED]"),
        ("phone", "[PHONE_REDACTED]"),
        ("address", "[ADDRESS_REDACTED]"),
        ("ip_address", "[IP_REDACTED]"),
        ("date_of_birth", "[DOB_REDACTED]"),
        ("passport", "[PASSPORT_REDACTED]"),
        ("drivers_license", "[DL_REDACTED]"),
        ("bank_account", "[ACCOUNT_REDACTED]"),
    };

    [Fact]
    public void DeclaresExactlyTenPiiTypesTheJsTierOneVocabulary()
    {
        var declaredTypes = Pii.Patterns.Select(p => p.Type).ToList();
        Assert.Equal(10, declaredTypes.Count);
        Assert.Equal(JsReferenceVocabulary.Select(v => v.Type), declaredTypes);
    }

    [Fact]
    public void EveryDeclaredPiiTypeHasALivePatternNoneAreNullEmptyOrDuplicated()
    {
        var seen = new HashSet<string>();
        foreach (var def in Pii.Patterns)
        {
            Assert.False(string.IsNullOrWhiteSpace(def.Type));
            Assert.NotNull(def.Pattern);
            Assert.False(string.IsNullOrWhiteSpace(def.Redaction));
            // A duplicate declaration is exactly as dangerous as a missing
            // one: it silently shadows a real pattern in DetectPii's
            // sequential-apply loop.
            Assert.True(seen.Add(def.Type), $"PII type '{def.Type}' is declared more than once");
        }
    }

    [Fact]
    public void RedactionLabelsAreByteIdenticalToTheJsSource()
    {
        var byType = Pii.Patterns.ToDictionary(p => p.Type, p => p.Redaction);
        foreach (var (type, redaction) in JsReferenceVocabulary)
        {
            Assert.True(byType.ContainsKey(type), $"declared-without-pattern gap: PII type '{type}' from the JS reference vocabulary has no .NET pattern");
            Assert.Equal(redaction, byType[type]);
        }
    }

    [Fact]
    public void EveryPatternActuallyMatchesAtLeastOneRealisticSample()
    {
        // A pattern present in the table but broken (never matches) is the
        // same practical failure as a missing pattern -- the type is
        // "declared" but nothing is ever detected under it. One representative
        // sample per type, taken from the JS/Go test fixtures.
        var samples = new Dictionary<string, string>
        {
            ["ssn"] = "123-45-6789",
            ["credit_card"] = "4111-1111-1111-1111",
            ["email"] = "jane.doe@example.com",
            ["phone"] = "555-123-4567",
            ["address"] = "123 Main Street",
            ["ip_address"] = "192.168.1.1",
            ["date_of_birth"] = "01/15/1990",
            ["passport"] = "AB1234567",
            ["drivers_license"] = "D123456789012",
            ["bank_account"] = "12345678901",
        };

        foreach (var def in Pii.Patterns)
        {
            Assert.True(samples.TryGetValue(def.Type, out var sample), $"no parity sample recorded for declared type '{def.Type}'");
            Assert.True(def.Pattern.IsMatch(sample!), $"pattern for '{def.Type}' does not match its own reference sample '{sample}'");
        }
    }

    [Fact]
    public void InjectionRulesetDeclaresExactlyTheThreeJsTypesAllWithLivePatterns()
    {
        Assert.Equal(new[] { "exfiltration_url", "instruction_override", "role_reassignment" }, InjectionHeuristics.Types);
        Assert.Equal(12, InjectionHeuristics.Patterns.Count);
        Assert.All(InjectionHeuristics.Patterns, p =>
        {
            Assert.Contains(p.Type, InjectionHeuristics.Types);
            Assert.NotNull(p.Pattern);
        });
    }
}

/// <summary>
/// SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS: every declared type has a positive
/// and a negative example, and the positive one is detected end to end.
/// </summary>
public class PiiTypeExamplesTests
{
    public static IEnumerable<object[]> Cases() => new[]
    {
        new object[] { "ssn", "SSN 123-45-6789 on file", "SSN 123456789 on file" },
        new object[] { "credit_card", "card 4111-1111-1111-1111 ok", "card 4111-1111-1111 ok" },
        new object[] { "email", "mail jane.doe@example.com now", "mail jane.doe at example dot com" },
        new object[] { "phone", "call 555-123-4567 now", "call 55-12 now" },
        new object[] { "address", "lives at 123 Main Street today", "lives on Main Street today" },
        new object[] { "ip_address", "host 192.168.1.1 up", "host 999.999.999.999 up" },
        new object[] { "date_of_birth", "born 01/15/1990 in", "born 13/45/1990 in" },
        new object[] { "passport", "passport AB1234567 seen", "passport ab1234567 seen" },
        new object[] { "drivers_license", "licence D1234567 seen", "licence d1234567 seen" },
        new object[] { "bank_account", "account 12345678901 open", "account 1234567 open" },
    };

    [Fact]
    public void EveryDeclaredTypeHasAnExampleCase()
    {
        var covered = Cases().Select(c => (string)c[0]).ToHashSet();
        foreach (var def in Pii.Patterns)
            Assert.True(covered.Contains(def.Type), $"declared type '{def.Type}' has no positive/negative test case");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void TypeDetectsPositiveAndRejectsNegative(string type, string positive, string negative)
    {
        var def = Pii.Patterns.Single(p => p.Type == type);
        Assert.True(def.Pattern.IsMatch(positive), $"{type}: positive example not matched");
        Assert.False(def.Pattern.IsMatch(negative), $"{type}: negative example wrongly matched");
        Assert.Contains(type, Pii.DetectPii(positive).Types);
    }
}

public class AgentTelemetryTests
{
    [Fact]
    public void GovernPassesAgentFieldsThroughToResultAndReceipt()
    {
        var ctx = new SessionContext { AgentId = "a-1", AgentRole = "worker", SessionId = "s-9", SessionTurn = 3 };
        var r = new TorkGovernance.Core.Tork().Govern("hello", new GovernOptions { SessionContext = ctx });
        Assert.Same(ctx, r.SessionContext);
        Assert.Same(ctx, r.Receipt.SessionContext);
        var json = System.Text.Json.JsonSerializer.Serialize(r.Receipt);
        Assert.Contains("\"session_context\":{\"agent_id\":\"a-1\",\"agent_role\":\"worker\",\"session_id\":\"s-9\",\"session_turn\":3}", json);
    }

    [Fact]
    public void GovernOmitsAgentFieldsWhenNotSet()
    {
        var r = new TorkGovernance.Core.Tork().Govern("hello");
        Assert.Null(r.Receipt.SessionContext);
        Assert.DoesNotContain("session_context", System.Text.Json.JsonSerializer.Serialize(r.Receipt));
    }

    [Fact]
    public void UnsetIndividualFieldsAreOmitted()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new SessionContext { SessionTurn = 1 });
        Assert.Equal("{\"session_turn\":1}", json);
    }
}
