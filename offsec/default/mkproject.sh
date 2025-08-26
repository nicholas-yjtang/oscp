#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
pushd $SCRIPTDIR || exit
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
cp setup_network.sh "$project_name/setup_network.sh"
cp mkpart.sh "$project_name/mkpart.sh"
cp part_template.sh "$project_name/part_template.sh"
#sed -i 's/\.\//\.\.\//g' "$project_name/$project_name.sh"
popd || exit 
