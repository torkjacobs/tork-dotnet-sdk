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

## Regional PII Detection (v1.1)

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
