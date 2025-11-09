#!/bin/bash

run_part_template() {
    echo "Running part_template"
    ip=$part_template_ip
    nmap_tcp
    snmp_enumerate 
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    source project_name.sh
    run_part_template
fi
