# ToolGood.SQLFirewall
SQL Firewall：Prevent SQL injection, 防sql注入 


## Quick start 快速上手
``` csharp
using ToolGood.SQLFirewall;

    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            ...

            var app = builder.Build();
            app.UseSQLFirewall_ServerHeader("ToolGood");
            app.UseSQLFirewall(SQLFirewallType.MsSQL);
            // set ignore Urls 设置忽略网址
            // app.UseSQLFirewall(SQLFirewallType.MsSQL, "/Admins/Logs/Ajax/GetLoginList", "/Admins/User/Ajax/*"); 
            
            ...
            app.Run();
        }
    }
```

### NOTE 注意

The last `*` character is a wildcard character

最后`*`符为通配符
