#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
pushd $SCRIPTDIR
project_name=$1
if [ -z "$project_name" ]; then
    echo "Usage: $0 <project_name>"
    exit 1
fi
if [ -d "$project_name" ]; then
    echo "$project_name already exists"
    exit 0
fi
mkdir -p "$project_name"
cp walk.sh "$project_name/$project_name.sh"
sed -i 's/\.\//\.\.\//g' "$project_name/$project_name.sh"
popd
