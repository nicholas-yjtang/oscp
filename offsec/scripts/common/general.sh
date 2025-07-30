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
    if [ ! -d "$project/log" ]; then
        echo "Log directory does not exist. Creating it now."
        mkdir -p "$project/log"
    fi
fi
project_name=$(basename "$project")
log_dir=$(realpath "$project"'/log')
trail_log=$(realpath "$project"'/log/trail.log')
tcpdump_log=$(realpath "$project"'/log/tcpdump.log')

remove_color_to_log() {
    cat | sed -u -E 's/\x1b\[[0-9;]*[mK]//g' | sed -u -E 's/\x1b\]0;.*\x07//g' | sed -u -E 's/\x1b\[0m//g' | sed -u -E 's/\x1b\[\?[0-9]+[hl]//g' | sed -u -E 's/\x1b\[C\x1b\[C\x1b\[C.*//g' | sed -u -E ':a;s/[^\x08]\x08//g;ta' | sed -u 's/\x07//g'
}