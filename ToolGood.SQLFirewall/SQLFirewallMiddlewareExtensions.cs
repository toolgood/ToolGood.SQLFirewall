namespace ToolGood.SQLFirewall
{
    using Microsoft.AspNetCore.Builder;

    /// <summary>
    /// Extension methods for adding the <see cref="SQLFirewallMiddleware"/> to an application.
    /// </summary>
    public static class SQLFirewallMiddlewareExtensions
    {
        /// <summary>
        /// set Server Header
        /// </summary>
        /// <param name="app"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseSQLFirewall_ServerHeader(this IApplicationBuilder app, string name = "Firewall")
        {
            return app.Use(async (context, next) => {
                context.Response.OnStarting(() => {
                    if (context.Response.Headers.Count > 1) {
                        context.Response.Headers.Remove("Server");
                        context.Response.Headers["Server"] = name;
                    }
                    return Task.CompletedTask;
                });
                context.Response.Headers["Server"] = name;
                await next.Invoke(context);
            });
        }

        /// <summary>
        /// Use SQL Firewall
        /// </summary>
        /// <param name="app"></param>
        /// <param name="firewallType"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseSQLFirewall(this IApplicationBuilder app, SQLFirewallType firewallType)
        {
            ArgumentNullException.ThrowIfNull(app);
            return app.UseMiddleware<SQLFirewallMiddleware>(firewallType);
        }

        /// <summary>
        /// Use SQL Firewall
        /// </summary>
        /// <param name="app"></param>
        /// <param name="firewallType">SQL Type</param>
        /// <param name="ignoreUrls">ignore Urls</param>
        /// <returns></returns>
        public static IApplicationBuilder UseSQLFirewall(this IApplicationBuilder app, SQLFirewallType firewallType, params string[] ignoreUrls)
        {
            ArgumentNullException.ThrowIfNull(app);
            return app.UseMiddleware<SQLFirewallMiddleware>(firewallType, ignoreUrls);
        }
    }
}