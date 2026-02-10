#!/bin/bash

snmp_enumerate() {
    if [[ ! -z $1 ]]; then
        target_ip=$1
    fi
    if [[ -z "$target_ip" ]]; then
        target_ip=$ip
        echo "Using default target IP: $target_ip"
    fi
    if [[ -f $log_dir/snmp_enumeration_${target_ip}.log ]]; then
        echo "SNMP enumeration log already exists for $target_ip"
        return 0
    fi
    local proxychain_command=""
    if [[ ! -z "$use_proxychain" ]] && [[ "$use_proxychain" == "true" ]]; then
        echo "Running SNMP enumeration with proxychains"
        proxychain_command="proxychains -q "
    fi
    if $proxychain_command nc -nuvz -w 3 $target_ip 161; then
        echo "SNMP service is running on $target_ip"
        results=$($proxychain_command onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $target_ip | grep $target_ip)
        echo "$results" | tee >(remove_color_to_log >> $log_dir/snmp_enumeration_${target_ip}.log)
        community=$(echo "$results" | head -n 1 | grep -oP $target_ip'\s+\[\K[^]]+')
        echo "SNMP Community: $community"
        if [[ -z "$community" ]]; then
            echo "No SNMP community found, using default 'public'"
            community="public"
        fi
        local snmp_command="$proxychain_command snmp-check -c $community $target_ip"
        echo $snmp_command
        eval $snmp_command | tee >(remove_color_to_log >> $log_dir/snmp_enumeration_${target_ip}.log)
        snmp_command="$proxychain_command snmpbulkwalk -v 2c -c $community $target_ip NET-SNMP-EXTEND-MIB::nsExtendObjects"
        eval $snmp_command | tee >(remove_color_to_log >> $log_dir/snmp_enumeration_${target_ip}.log)
    else
        echo "SNMP service is not running on $target_ip"
        touch $log_dir/snmp_enumeration_${target_ip}.log
    fi
    echo "SNMP enumeration completed for $target_ip"
}