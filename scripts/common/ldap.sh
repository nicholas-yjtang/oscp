#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

run_ldapsearch_anonymous() {
    if [[ -z $target_ip ]]; then
        echo "target_ip is not set"
        return 1
    fi
    if [[ -z $base_dn ]]; then
        base_dn=$(get_base_dn_from_domain)
    fi
    echo "Running ldapsearch anonymous on $target_ip with base DN $base_dn"
    if [[ -f "log/ldapsearch_anonymous_$target_ip.log" ]]; then
        echo "log/ldapsearch_anonymous_$target_ip.log already exists, skipping ldapsearch"
        return 0
    fi
    ldapsearch -x -H ldap://$target_ip -b "$base_dn" | tee >(remove_color_to_log >> "log/ldapsearch_anonymous_$target_ip.log")
}

get_base_dn_from_domain() {
    if [[ -z $domain ]]; then
        echo "domain is not set"
        return 1
    fi
    IFS='.' read -ra ADDR <<< "$domain"
    local base_dn=""
    for i in "${ADDR[@]}"; do
        if [[ -z $base_dn ]]; then
            base_dn="DC=$i"
        else
            base_dn+=",DC=$i"
        fi
    done
    echo "$base_dn"
}