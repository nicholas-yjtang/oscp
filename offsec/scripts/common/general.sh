#!/bin/bash
if [ -z "$project" ]; then
    echo "Project is not set. Please set the project variable."
    exit 1
fi

project_dir=$(dirname $project)
if [ ! -z "$project_dir" ]; then
    if [ ! -d "$project_dir" ]; then
        echo "Project directory $project_dir does not exist. Creating it now."
        mkdir -p "$project_dir"
    fi
fi
project_name=$(basename "$project")
trail_log="$project"'_trail.log'
gobuster_log="$project"'_gobuster.log'
nmap_log="$project"'_nmap.log'