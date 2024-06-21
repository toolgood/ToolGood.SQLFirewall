namespace ToolGood.SQLFirewall.Test
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            SQLFirewallType firewallType = SQLFirewallType.MsSQL;
            SQLFirewallType remove = SQLFirewallType.ALL ^ firewallType;

            // 数据来源 https://github.com/payloadbox/sql-injection-payload-list
            var files = Directory.GetFiles("Datas", "*.txt", SearchOption.AllDirectories);

            HashSet<string> sqls = new HashSet<string>();
            foreach (var file in files) {
                if (remove.HasFlag(SQLFirewallType.MsSQL)) { if (file.Contains("MSSQL")) continue; }
                if (remove.HasFlag(SQLFirewallType.MySQL)) { if (file.Contains("MySQL")) continue; }
                if (remove.HasFlag(SQLFirewallType.NoSQL)) { if (file.Contains("NoSQL")) continue; }
                if (remove.HasFlag(SQLFirewallType.Oracle)) { if (file.Contains("Oracle")) continue; }
                if (remove.HasFlag(SQLFirewallType.PgSQL)) { if (file.Contains("PostgresSQL")) continue; }
                if (remove.HasFlag(SQLFirewallType.DB2)) { if (file.Contains("DB2")) continue; }

                var txts = File.ReadAllLines(file);
                foreach (var txt in txts) {
                    sqls.Add(txt);
                }
            }

            var notFind = new List<string>();
            foreach (var sql in sqls) {
                if (sql == "%00") {
                }

                var find = false;
                if (SQLFirewallMiddleware.IsMatch(sql, firewallType)) {
                    find = true;
                    continue;
                }
                if (find == false) {
                    notFind.Add(sql);
                }
            }
            Console.WriteLine(notFind.Count);

            File.WriteAllLines("notFind.txt", notFind.ToArray());
        }
    }
}