#!/bin/bash
source ../setup.sh

if [[ -z $project_name ]]; then
    echo "Error: project_name is not set"
    exit 1
fi

if [[ -z $1 ]]; then
    echo "Error: Part name is not set"
    exit 1
fi

part_name=$1
if [[ ! -f "$part_name.sh" ]]; then
	cp part_template.sh "$part_name.sh"
	sed -E -i "s/part_template/$part_name/g" "$part_name.sh"
	sed -E -i "s/project_name/$project_name/g" "$part_name.sh"
fi
