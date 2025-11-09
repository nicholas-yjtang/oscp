#!/bin/bash

encode_bash_payload() {
    local payload="$1"
    payload=$(encode_base64 "$payload")
    payload="echo $payload|base64 -d"
    payload="\$($payload);"
    encode_space
    if [[ ! -z $encoding_type ]] && [[ $encoding_type == "minimal" ]]; then
        echo "$payload"
        return 0
    fi
    payload="eval $payload"
    encode_space
    echo "$payload"
}

encode_python_payload() {
    local payload="$1"
    payload=$(encode_base64 "$payload")
    payload="import base64,os;os.system(base64.b64decode(\\\"$payload\\\"))"
    if [[ ! -z $encoding_type ]] && [[ $encoding_type == "minimal" ]]; then
        echo "$payload"
        return 0
    fi
    payload="python -c \"$payload\""
    payload="\$($payload);"
    payload="eval $payload"
    echo "$payload"
}

encode_space() {
    if [[ ! -z $encode_space ]] && [[ $encode_space == true ]]; then
        payload=$(encode_space_ifs "$payload")
    fi
}

encode_perl_payload() {
    local payload="$1"
    payload=$(echo "$payload" | sed -E 's/"/\\"/g')
    payload=$(perl -e "print(unpack('H*',\"$payload\"))")
    local payload_length=${#payload}
    payload="system(pack(qq,H$payload_length,,qq,$payload,))"
    if [[ ! -z $encoding_type ]] && [[ $encoding_type == "minimal" ]]; then
        echo "$payload"
        return 0
    fi
    payload="perl -e '$payload'"
    payload="\$($payload);"
    payload="eval $payload"
    encode_space
    echo "$payload"
}

encode_base64() {
    local input="$1"
    echo -n "$input" | base64 -w 0
}

encode_space_ifs() {
    local input="$1"
    echo "$input" | sed -E 's/ /$\{IFS\}/g'
}
