using Microsoft.AspNetCore.Http;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ToolGood.SQLFirewall
{
    /// <summary>
    /// SQL Firewall Middleware
    /// </summary>
    public class SQLFirewallMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly SQLFirewallType _firewallType;
        private readonly HashSet<string> _ignoreUrls;
        private readonly List<string> _ignoreUrls2;
        private readonly List<Regex> sqlRegexs;

        /// <summary>
        ///
        /// </summary>
        /// <param name="next"></param>
        /// <param name="firewallType"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public SQLFirewallMiddleware(RequestDelegate next, SQLFirewallType firewallType)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _firewallType = firewallType;
            _ignoreUrls = null;
            _ignoreUrls2 = null;
            sqlRegexs = GetSqlRegexes(firewallType);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="next"></param>
        /// <param name="firewallType"></param>
        /// <param name="ignoreUrls"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public SQLFirewallMiddleware(RequestDelegate next, SQLFirewallType firewallType, string[] ignoreUrls)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _firewallType = firewallType;
            _ignoreUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _ignoreUrls2 = new List<string>();
            if (ignoreUrls != null) {
                foreach (var url in ignoreUrls) {
                    if (url.EndsWith('*')) {
                        _ignoreUrls2.Add(url.Substring(0, url.Length - 1));
                    } else {
                        _ignoreUrls.Add(url);
                    }
                }
            }
            sqlRegexs = GetSqlRegexes(firewallType);
        }

        /// <summary>
        /// Invoke
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task Invoke(HttpContext context)
        {
            // 处理 忽略网址
            if (_ignoreUrls != null && _ignoreUrls.Contains(context.Request.Path)) {
                await _next.Invoke(context);
                return;
            }
            if (_ignoreUrls2 != null && _ignoreUrls2.Count > 0) {
                var url = context.Request.Path.ToString();
                foreach (var item in _ignoreUrls2) {
                    if (url.StartsWith(item, StringComparison.OrdinalIgnoreCase)) {
                        await _next.Invoke(context);
                        return;
                    }
                }
            }

            var list = sqlRegexs;
            foreach (var item in context.Request.Query) {
                var sql = SqlConversionStandard(item.Value);
                if (IsMatch(sql, list)) {
                    context.Response.StatusCode = 403;
                    return;
                }
            }
            if (context.Request.Method == "POST") {
                context.Request.EnableBuffering();
                if (context.Request.HasFormContentType) {
                    foreach (var item in context.Request.Form) {
                        var sql = SqlConversionStandard(item.Value);
                        if (IsMatch(sql, list)) {
                            context.Response.StatusCode = 403;
                            return;
                        }
                    }
                } else if (context.Request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase)) {
                    StreamReader reader = new StreamReader(context.Request.Body);
                    var jsonStr = await reader.ReadToEndAsync();
                    try {
                        var json = JsonNode.Parse(jsonStr);
                        if (IsMatch(json, list)) {
                            context.Response.StatusCode = 403;
                            return;
                        }
                    } catch (Exception) { }
                    context.Request.Body.Position = 0;
                }
            }
            await _next.Invoke(context);
        }

        private bool IsMatch(JsonNode jsonNode, List<Regex> regexes)
        {
            if (jsonNode is JsonValue jsonValue) {
                if (jsonValue.TryGetValue<string>(out string str)) {
                    var sql = SqlConversionStandard(str);
                    return IsMatch(sql, regexes);
                }
            } else if (jsonNode is JsonObject jobject) {
                var enumerator = jobject.GetEnumerator();
                while (enumerator.MoveNext()) {
                    var current = enumerator.Current;
                    if (IsMatch(current.Value, regexes)) { return true; }
                }
            } else if (jsonNode is JsonArray jsonArray) {
                foreach (var item in jsonArray) {
                    if (IsMatch(item, regexes)) { return true; }
                }
            }
            return false;
        }

        private bool IsMatch(string sql, List<Regex> regexes)
        {
            foreach (var regStr in regexes) {
                if (regStr.IsMatch(sql)) { return true; }
            }
            return false;
        }

        /// <summary>
        /// static function
        /// </summary>
        /// <param name="text"></param>
        /// <param name="firewallType"></param>
        /// <returns></returns>
        public static bool IsMatch(string text, SQLFirewallType firewallType)
        {
            var sql = SqlConversionStandard(text);
            var list = GetSqlRegexes(firewallType);
            foreach (var item in list) {
                if (item.IsMatch(sql)) { return true; }
            }
            return false;
        }

        private static List<Regex> GetSqlRegexes(SQLFirewallType firewallType)
        {
            var list = new List<string>();
            list.Add(@"ldap:|rmi:|JDBC4Connection|trax\.TemplatesImpl");
            //list.Add(@"<[^>]+?style=[\w]+?:expression\(|\bonmouse(over|move)=\b|\b(alert|confirm|prompt)\b|<[^>]*?=[^>]*?&#[^>]*?>");

            list.Add(@"('|""|;|`)\){0,9}.*( –|--|/\*|#)");
            if (firewallType.HasFlag(SQLFirewallType.MySQL)) {
                list.Add(@"('|""|;|`)\){0,9} ?(or|\|\|) ?\({0,9}('|""|;|`)");
                list.Add(@"(or|and|\|\||&&) \({1,3}EXISTS\){1,3}");
                list.Add(@"(or|and|\|\||&&) \({0,3}(true|false|1|0|['""`]?[a-z_0-9]+['""`]? ?(>|>=|<|<=|=|==|<>) ?['""`]?[a-z_0-9]+['""`]?|['""`]['""`] ?= ?['""`])");
                list.Add(@"(or|and|\|\||&&) \({0,3}[a-z_0-9]+ between \d+ and \d+");
                list.Add(@"(or|and|\|\||&&) \({0,3}(username|uname|userid|id|uid|user|full_name|user_name)( ?=| is)");
                list.Add(@"(or|and|\|\||&&) \({0,3}(username|uname|userid|id|uid|user|full_name|user_name) like ('%|\({0,3}char\(37\))");
            } else {
                list.Add(@"('|""|;|`)\){0,9} ?or ?\({0,9}('|""|;|`)");
                list.Add(@"(or|and) \({1,3}EXISTS\){1,3}");
                list.Add(@"(or|and) \({0,3}(true|false|1|0|['""`]?[a-z_0-9]+['""`]? ?(>|>=|<|<=|=|==|<>) ?['""`]?[a-z_0-9]+['""`]?|['""`]['""`] ?= ?['""`])");
                list.Add(@"(or|and) \({0,3}[a-z_0-9]+ between \d+ and \d+");
                list.Add(@"(or|and) \({0,3}(username|uname|userid|id|uid|user|full_name|user_name)( ?=| is| in)");
                list.Add(@"(or|and) \({0,3}(username|uname|userid|id|uid|user|full_name|user_name) like ('%|\({0,3}char\(37\))");
            }

            list.Add(@"UNION.+?SELECT|SELECT.+?INTO|UPDATE.+?SET|INSERT INTO|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|DATABASE|procedure|Function)");
            list.Add(@"\bselect \({0,3}(\*|count|top|DISTINCT|current_user|session_user|version\(|current_database\(|CHAR\(|bin\()");

            list.Add(@"\b(call|execute|exec|grant|ORDER BY|group by|CASE WHEN|INNER JOIN|LEFT JOIN|RIGHT JOIN|FULL OUTER JOIN|FULL JOIN|declare|BACKUP)\b");

            list.Add(@"\bsleep\(\d+\)|\bsleep\(__TIME__\)|\band substring\(password");

            //数据库 库表
            //MySQL
            if (firewallType.HasFlag(SQLFirewallType.MySQL)) {
                list.Add(@"\b(handler|load_file|outfile|benchmark)\b");
                list.Add(@"\b(INFORMATION_SCHEMA|mysql|performance_schema)\b");
            }
            if (firewallType.HasFlag(SQLFirewallType.MsSQL)) {
                list.Add(@"\b(sp_password|waitfor delay)\b|@@servername|@@microsoftversione|@@version");
                list.Add(@"\b(master|msdb|mssqlweb|tempdb|sysaltfiles|syscharsets|sysconfigures|syscurconfigs|sysdatabases|syslanguages|syslogins|sysoledbusers|sysprocesses|sysremotelogins|syscolumns|sysconstrains|sysfilegroups|sysfiles|sysforeignkeys|sysindexs|sysmenbers|sysobjects|syspermissions|systypes|sysusers)\b");
            }
            if (firewallType.HasFlag(SQLFirewallType.PgSQL)) {
                list.Add(@"\b(current_setting)\b");
                list.Add(@"\b(pg_class|pg_shadow|pg_group|pg_sleep)\b");
            }
            if (firewallType.HasFlag(SQLFirewallType.Oracle)) {
                list.Add(@"\b(dba_users|dba_segments|dba_extents|dba_objects|dba_tablespaces|dba_data_files|dba_temp_files|dba_rollback_segs|dba_ts_quota|dba_free_space|dba_profiles|dba_sys_privs|dba_tab_privs|dba_col_privs|dba_role_privs|dba_audit_trail|dba_stmt_audit_opts|dba_audit_object|dba_audit_session|dba_indexes)\b");
                list.Add(@"\b(user_objects|user_source|user_segments|user_tables|user_tab_columns|user_constraints|user_sys_privs|user_tab_privs|user_col_privs|user_role_privs|user_indexes|user_ind_columns|user_cons_columns|user_clusters|user_clu_columns|user_cluster_hash_expressions)\b");
                list.Add(@"\b(v$database|v$datafile|v$controlfile|v$logfile|v$instance|v$log|v$loghist|v$sga|v$parameter|v$process|v$bgprocess|v$controlfile_record_section|v$thread|v$datafile_header|v$archived_log|v$archive_dest|v$logmnr_contents|v$logmnr_dictionary|v$logmnr_logs|v$tablespace|v$tempfile|v$filestat|v$undostat|v$rollname|v$session|v$transaction|v$rollstat|v$pwfile_users|v$sqlarea|v$sql|v$sysstat)\b");
                list.Add(@"\b(all_users|all_objects|all_def_audit_opts|all_tables|all_indexes|session_roles|session_privs|index_stats)\b");
                list.Add(@"\b(tz_offset|to_timestamp_tz|utl_http.request|myappadmin.adduser)\b");
            }
            if (firewallType.HasFlag(SQLFirewallType.DB2)) {
                list.Add(@"\b(sysibm.sysdummy1|syscat.dbauth|syscat.tabauth|sysibm.systables|sysibm.syscolumns|sysibm.sysversions|syscat.schemata)\b");
            }
            if (firewallType.HasFlag(SQLFirewallType.NoSQL)) {
                list.Add(@"[\$](where|or|ne|comment)|this.password");
            }

            List<Regex> regexes = new List<Regex>();
            foreach (string item in list) {
                regexes.Add(new Regex(item, RegexOptions.IgnoreCase | RegexOptions.IgnoreCase));
            }
            return regexes;
        }

        private static string SqlConversionStandard(string sql)
        {
            var txt = Regex.Replace(sql, @"/\*.*?\*/", " ", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            // 经测试 select\x201 是无效代码，   ‘|’|′ 不会转成 ' 也是无效代码
            //txt = Regex.Replace(txt, @"( |\t|\r|\n|\t|\v|\f|%20|\\x20|%00|\\x00|&nbsp;|&ensp;|&emsp;|&thinsp;|&zwnj;|&zwj;)+", " ", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            //txt = Regex.Replace(txt, @"(\\x27|%27|‘|’|′|&apos;)", "'", RegexOptions.IgnoreCase | RegexOptions.Compiled);

            txt = Regex.Replace(txt, @"( |\t|\r|\n|\t|\v|\f|\x00|\s)+", " ", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            return txt;
        }
    }
}