# Tork Governance .NET SDK

On-device AI governance for .NET applications. PII detection, redaction, and cryptographic compliance receipts.

## Installation

```bash
dotnet add package TorkGovernance
```

## Quick Start

```csharp
using TorkGovernance.Core;

var tork = new Tork();

var result = tork.Govern("Contact john@example.com or call 555-123-4567");

Console.WriteLine(result.Action);  // "redact"
Console.WriteLine(result.Output);  // "Contact [EMAIL_REDACTED] or call [PHONE_REDACTED]"
```

## Scanning tool results

A tool result returned by an MCP server — or any external system you do not control — is untrusted input that is about to be appended to a model's context. `Tork.ScanToolResult` scans it first, on-device, for PII and prompt injection:

```csharp
using TorkGovernance.Core;

var tork = new Tork();
var report = tork.ScanToolResult(
    new ToolResultScanInput
    {
        ToolName = "lookup_customer",
        ServerUri = "mcp://crm.internal/customers",
        Payload = toolResult, // Dictionary<string, object?> / List<object?> tree, or a bare string
    },
    new ToolResultScanOptions { BlockOnInjection = true }
);

if (report.Blocked)
{
    Console.WriteLine(report.Reason); // do not append anything
}
else
{
    AppendToContext(report.Sanitized); // PII masked in place
}

report.Findings;
// [{ Kind = Pii, Type = "email", Count = 1, Location = "$.content[0].text" },
//  { Kind = Injection, Type = "heuristic:instruction_override", Count = 1, Location = "$.content[0].text" }]
```

There is also a standalone `ToolResultScan.Scan(input, options)` call with the same shape that returns `ToolResultScanResult { Sanitized, Findings, Blocked, Reason }` and produces no receipt.

- **PII uses the same on-device detector as `Govern`'s Tier-1 vocabulary** — the 10-type basic PII set (ssn, credit_card, email, phone, address, ip_address, date_of_birth, passport, drivers_license, bank_account) with JS-SDK-identical type labels and redaction markers. Matches are masked in place; the payload structure is otherwise unchanged, and a clean payload comes back as the same object you passed in. **Parity tier: Tier 1.** This SDK does not implement the Python SDK's regional/industry pattern tier (AU/US/GB/EU/AE/... profiles) — see the note under [Regional PII Detection](#regional-pii-detection-v11) below.
- **Injection detection is heuristic.** A conservative pattern set (`tork-injection-heuristics-v1`) covering instruction-override phrases, role reassignment, and exfiltration URLs. Every injection finding is typed `heuristic:<name>` because that is exactly what it is: a regex match over untrusted text, with false positives and false negatives, not a verified determination. Without `BlockOnInjection`, matches are reported and the result is still returned; with it, `Sanitized` is `null` so no masked copy can be appended by accident.
- **Zero network calls.** The scan is pure and synchronous. The payload never leaves the machine.
- **Recorded on the receipt as counts only.** `receipt.tool_result_scan` (`GovernanceReceipt.ToolResultScan`) carries `attested_by: "client"`, `capture_mode: "edge"`, the tool name and server URI, counts by kind and type, the blocked flag, and the SDK version. It never carries the payload, a matched value, or a location path. `receipt.Action` follows the same four-way mapping as the JS and Go SDKs: blocked → `deny`; an injection finding present → `escalate`; otherwise a PII finding present → `redact`; otherwise → `allow`.

**This is a client-side, client-attested control.** The scan runs in your process, and the receipt says so: Tork did not execute it and cannot verify it ran at all — the same honest boundary as every other edge attestation this SDK produces. **Gateway-side enforcement, where a caller cannot skip the scan, is a separate and later control.** Do not read a `tool_result_scan` block as proof that every tool result reaching a model was scanned; read it as a record of the scans a caller chose to run and report.

### Supported PII types (Tier 1)

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| Address | 123 Main Street | [ADDRESS_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | 01/15/1990 | [DOB_REDACTED] |
| Passport | AB1234567 | [PASSPORT_REDACTED] |
| Driver's License | D1234567 | [DL_REDACTED] |
| Bank Account | 12345678901234 | [ACCOUNT_REDACTED] |

## Regional PII Detection (v1.1)

> **Known gap:** `GovernOptions.Region` and `Industry` are currently accepted
> and threaded through to `GovernanceResult`, but no region- or
> industry-specific pattern is yet wired into detection — `Govern` always
> runs the same Tier-1 vocabulary regardless of these values. The examples
> below (Emirates ID, Aadhaar, ICD-10, ...) describe the intended surface,
> not current behavior. Tracked for a follow-up change; do not rely on
> region/industry patterns firing today.

Activate country-specific and industry-specific PII patterns:

```csharp
var tork = new Tork();

// UAE regional detection — Emirates ID, +971 phone, PO Box
var result = tork.Govern(
    "Emirates ID: 784-1234-1234567-1",
    new GovernOptions { Region = new[] { "ae" } }
);

// Multi-region + industry
var result = tork.Govern(
    "Aadhaar: 1234 5678 9012, ICD-10: J45.20",
    new GovernOptions { Region = new[] { "in" }, Industry = "healthcare" }
);

// Available regions: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR
// Available industries: healthcare, finance, legal
```

## ASP.NET Core Integration

```csharp
// Program.cs
builder.Services.AddTorkGovernance(config =>
{
    config.DefaultAction = "redact";
    config.PolicyVersion = "1.0.0";
});

app.UseTorkGovernance();
```

Access in controllers:

```csharp
[ApiController]
public class UsersController : ControllerBase
{
    [HttpPost]
    public IActionResult Create()
    {
        var tork = HttpContext.Items["Tork"] as Tork;
        var receipts = HttpContext.Items["TorkReceipts"] as List<GovernanceReceipt>;

        // Your logic here...
    }
}
```

## Documentation

Visit [tork.network](https://tork.network) for full documentation.
