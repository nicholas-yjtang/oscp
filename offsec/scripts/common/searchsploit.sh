#!/bin/bash
run_searchsploit() {
    echo "Running Searchsploit..."
    local id="$1"
    local exploit_filename=$(searchsploit --disable-colour "$id" | grep -oP '\K'$id'[^ ]+')
    if [[ -f "$exploit_filename" ]]; then
        echo "$exploit_filename already exists, skipping SearchSploit"       
        return 
    fi    
    echo "Downloading exploit with ID: $id"
    searchsploit -m $id
}