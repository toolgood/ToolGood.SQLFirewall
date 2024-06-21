using ToolGood.SQLFirewall;

namespace ToolGood.Navigation
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddReverseProxy()
                .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
                ;

            var app = builder.Build();

            app.UseSQLFirewall_ServerHeader("ToolGood");
            //app.UseSQLFirewall(SQLFirewallType.MsSQL);
            app.UseSQLFirewall(SQLFirewallType.MsSQL, "/Admins/Logs/Ajax/GetLoginList", "/Admins/User/Ajax/*");

            app.MapReverseProxy();
            app.Run();
        }
    }
}