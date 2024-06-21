namespace ToolGood.SQLFirewall
{
    /// <summary>
    /// SQL Type
    /// </summary>
    [Flags]
    public enum SQLFirewallType
    {
        /// <summary>
        /// MsSQL  sqlserver
        /// </summary>
        MsSQL = 1,

        /// <summary>
        /// MySQL
        /// </summary>
        MySQL = 2,

        /// <summary>
        /// PostgresSQL
        /// </summary>
        PgSQL = 4,

        /// <summary>
        /// Oracle
        /// </summary>
        Oracle = 8,

        /// <summary>
        /// DB2
        /// </summary>
        DB2 = 16,

        /// <summary>
        /// NoSQL
        /// </summary>
        NoSQL = 32,

        /// <summary>
        /// ALL
        /// </summary>
        ALL = MsSQL | MySQL | PgSQL | Oracle | DB2 | NoSQL
    }
}