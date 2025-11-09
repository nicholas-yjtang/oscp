#!/bin/bash

run_part_template() {
    echo "Running part_template"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    source project_name.sh
    run_part_template
fi