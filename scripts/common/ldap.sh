#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

run_ldapsearch() {
    if [[ -z $target_ip ]]; then
        echo "target_ip is not set"
        return 1
    fi
    if [[ -z $base_dn ]]; then
        base_dn=$(get_base_dn_from_domain)
    fi
    local ldap_authhentication=""
    if [[ -z $ldap_bind_dn ]] && [[ -z $password ]]; then
        echo "ldap_bind_dn and password are not set, running ldapsearch anonymous"
    else
        echo "ldap_bind_dn and password are set. Using simple authentication"
        ldap_authhentication="-D \"$ldap_bind_dn,$base_dn\" -w \"$password\""
        echo "$ldap_authhentication"
    fi
    echo "Running ldapsearch on $target_ip with base DN $base_dn"
    if [[ -f "log/ldapsearch_$target_ip.log" ]]; then
        echo "log/ldapsearch_$target_ip.log already exists, skipping ldapsearch"
        return 0
    fi
    local command="ldapsearch -x -H ldap://$target_ip -b \"$base_dn\" $ldap_authhentication"
    echo $command
    eval $command | tee >(remove_color_to_log >> "log/ldapsearch_$target_ip.log")
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