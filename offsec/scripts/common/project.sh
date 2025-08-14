#!/bin/bash

if [ -z "$project" ]; then
    echo "WARNING Project is not set. Going to assume this the current directory is the project"
    project=$(pwd)
fi

project_dir=$(dirname $project)
if [ ! -z "$project_dir" ]; then
    if [ ! -d "$project_dir" ]; then
        echo "Project directory $project_dir does not exist. Creating it now."
        mkdir -p "$project_dir"
    fi
    if [ ! -d "$project/log" ]; then
        echo "Log directory does not exist. Creating it now."
        mkdir -p "$project/log"
    fi
fi
project_name=$(basename "$project")
log_dir=$(realpath "$project"'/log')
trail_log=$(realpath "$project"'/log/trail.log')
tcpdump_log=$(realpath "$project"'/log/tcpdump.log')
