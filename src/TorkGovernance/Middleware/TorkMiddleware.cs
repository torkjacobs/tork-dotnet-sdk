using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using TorkGovernance.Core;

namespace TorkGovernance.Middleware;

/// <summary>
/// ASP.NET Core middleware for Tork Governance.
/// </summary>
public class TorkMiddleware
{
    private readonly RequestDelegate _next;
    private readonly Tork _tork;
    private readonly TorkMiddlewareOptions _options;

    public TorkMiddleware(RequestDelegate next, Tork tork, TorkMiddlewareOptions? options = null)
    {
        _next = next;
        _tork = tork;
        _options = options ?? new TorkMiddlewareOptions();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var receipts = new List<GovernanceReceipt>();

        // Govern query parameters
        if (_options.GovernInput)
        {
            foreach (var (key, values) in context.Request.Query)
            {
                foreach (var value in values)
                {
                    if (!string.IsNullOrEmpty(value))
                    {
                        var result = _tork.Govern(value);
                        receipts.Add(result.Receipt);
                    }
                }
            }
        }

        // Govern request body
        if (_options.GovernInput && _options.GovernBody && context.Request.ContentLength > 0)
        {
            context.Request.EnableBuffering();

            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;

            if (!string.IsNullOrEmpty(body))
            {
                var result = _tork.Govern(body);
                receipts.Add(result.Receipt);
            }
        }

        // Store in context
        context.Items["Tork"] = _tork;
        context.Items["TorkReceipts"] = receipts;

        // Capture response if governing output
        if (_options.GovernOutput)
        {
            var originalBodyStream = context.Response.Body;
            using var responseBody = new MemoryStream();
            context.Response.Body = responseBody;

            await _next(context);

            context.Response.Body.Seek(0, SeekOrigin.Begin);
            var responseText = await new StreamReader(context.Response.Body).ReadToEndAsync();
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            if (!string.IsNullOrEmpty(responseText) &&
                context.Response.ContentType?.Contains("application/json") == true)
            {
                var result = _tork.Govern(responseText);
                receipts.Add(result.Receipt);

                if (result.Action == "redact")
                {
                    var governedBytes = Encoding.UTF8.GetBytes(result.Output);
                    context.Response.ContentLength = governedBytes.Length;
                    await originalBodyStream.WriteAsync(governedBytes);
                }
                else
                {
                    await responseBody.CopyToAsync(originalBodyStream);
                }
            }
            else
            {
                await responseBody.CopyToAsync(originalBodyStream);
            }
        }
        else
        {
            await _next(context);
        }
    }
}

/// <summary>
/// Options for TorkMiddleware.
/// </summary>
public class TorkMiddlewareOptions
{
    public bool GovernInput { get; set; } = true;
    public bool GovernOutput { get; set; } = true;
    public bool GovernBody { get; set; } = true;
}
