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
