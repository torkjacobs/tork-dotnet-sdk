using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using TorkGovernance.Core;

namespace TorkGovernance.Middleware;

/// <summary>
/// Extension methods for ASP.NET Core integration.
/// </summary>
public static class TorkExtensions
{
    /// <summary>
    /// Add Tork Governance services to the DI container.
    /// </summary>
    public static IServiceCollection AddTorkGovernance(
        this IServiceCollection services,
        Action<TorkConfig>? configure = null)
    {
        var config = new TorkConfig();
        configure?.Invoke(config);

        services.AddSingleton(config);
        services.AddSingleton<Tork>();

        return services;
    }

    /// <summary>
    /// Use Tork Governance middleware.
    /// </summary>
    public static IApplicationBuilder UseTorkGovernance(
        this IApplicationBuilder app,
        TorkMiddlewareOptions? options = null)
    {
        var tork = app.ApplicationServices.GetRequiredService<Tork>();
        return app.UseMiddleware<TorkMiddleware>(tork, options);
    }
}
