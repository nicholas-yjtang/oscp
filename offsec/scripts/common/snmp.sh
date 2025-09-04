#!/bin/bash

snmp_enumerate() {
    if [[ ! -z $1 ]]; then
        target_ip=$1
    fi
    if [[ -z "$target_ip" ]]; then
        echo "target_ip is not set"
        return 1
    fi
    results=$(onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $target_ip | grep $target_ip)
    echo "$results" | tee -a $log_dir/snmp_enumeration_${target_ip}.log
    community=$(echo "$results" | head -n 1 | grep -oP $target_ip'\s+\[\K[^]]+')
    echo "SNMP Community: $community"
    snmp-check -c $community $target_ip | tee -a $log_dir/snmp_enumeration_${target_ip}.log
    snmpbulkwalk -v 2c -c $community $target_ip NET-SNMP-EXTEND-MIB::nsExtendObjects | tee -a $log_dir/snmp_enumeration_${target_ip}.log
}