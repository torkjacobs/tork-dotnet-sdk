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

## Country PII detection

23 country profiles, 50 patterns and 20 check digits, generated from Tork's own
country registry (bundle `1.0.0`) and computed entirely on-device.

Countries: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE,
MU, MX, MY, PK, SG, TH.

A country's patterns switch on when the text activates that country — the same
content signals the cloud uses — so ordinary business text is not measured
against 50 national-identifier patterns it could never contain. On the
1,159-line business corpus this SDK is tested against, nothing is redacted.

```csharp
using TorkGovernance.Core;

var r = Pii.DetectPii("South African ID number 8001015009087 for the FICA check.");
r.Regions;       // ["ZA"]
r.CountryLabels; // ["ZA_ID"]
r.RedactedText;  // "South African ID number [ZA_ID_REDACTED] for the FICA check."
```

Pass `Region` to force profiles on when you already know the jurisdiction:

```csharp
var tork = new Tork();
var result = tork.Govern(
    "Documento 529.982.247-25 arquivado.",
    new GovernOptions { Region = new[] { "br" } });
// result.Output == "Documento [CPF_REDACTED] arquivado."
```

Three gates keep the false-positive rate down, and all three must pass:

1. **Activation** — one of the country's content signals fires.
2. **Keyword** — for 18 of the 24 national, tax and health identifiers, one of
   the identifier's keywords must appear within 60 characters before the match
   or 40 after.
3. **Check digit** — for the 10 identifiers whose issuing authority publishes
   the algorithm, a number of the right shape that fails its check digit is not
   that country's identifier. Where the algorithm is community-sourced rather
   than authority-published (`ca_sin`, `emirates_id`, `de_tax_id`, `kr_rrn`,
   `sa_national_id`) the checksum is advisory and never rejects a match.

Still cloud-only, and not in this SDK: the near-miss fallback, the slot,
context, gravity and name layers, industry profiles, and org configuration.

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
